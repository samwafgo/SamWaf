// Package supervisor 实现优雅升级的常驻监护进程。
//
// 它被服务管理器(kardianos/SCM/systemd)托管、永不为升级而退出，负责：
//   - 拉起并监护 Worker 子进程（业务引擎），崩溃自愈；
//   - 通过控制通道(wafipc)与 Worker 通信；
//   - 编排滚动升级：起新 Worker(takeover/REUSEPORT 同端口并存) → 新就绪 → 老 Worker 优雅排空退出；
//   - 升级失败时保留老 Worker、回滚，保证业务零中断。
//
// 端口由 Worker 自持(REUSEPORT)，Supervisor 不持有任何业务/管理端口。
package supervisor

import (
	"SamWaf/common/zlog"
	"SamWaf/wafipc"
	"SamWaf/wafupdate"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Options Supervisor 配置。
type Options struct {
	ExePath      string // 当前可执行文件路径（用于 spawn Worker）
	DataDir      string // 数据目录（存放 supervisor.state）
	CtrlPort     int    // 控制通道端口，0 表示由系统分配
	Token        string // 鉴权 token，空则自动生成
	DrainTimeout int    // Worker 排空超时(秒)
	ReadyTimeout int    // 升级时等待新 Worker READY 的超时(秒)
}

type workerState struct {
	pid      int
	proc     *os.Process
	version  string
	takeover bool

	mu    sync.Mutex // 串行化向该 worker 的写
	conn  *wafipc.Conn
	state string // starting / active / draining / gone
	beats time.Time
	conns int64
}

func (w *workerState) send(m wafipc.Message) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn != nil {
		_ = w.conn.Send(m)
	}
}

// Supervisor 监护器。
type Supervisor struct {
	opts     Options
	ln       net.Listener
	ctrlAddr string
	token    string

	mu            sync.Mutex
	workers       map[int]*workerState
	activePID     int
	upgrading     bool
	shuttingDown  bool
	crashTimes    []time.Time
	lastUpgradeAt time.Time // 上次升级切换到新版本的时刻；仅在此后"观察期"内连续崩溃才判坏版本回滚

	readyMu sync.Mutex
	readyCh map[int]chan struct{} // 按 pid 的 READY 通知

	done chan struct{}
}

// New 创建 Supervisor。
func New(opts Options) *Supervisor {
	if opts.DrainTimeout <= 0 {
		opts.DrainTimeout = 30
	}
	if opts.ReadyTimeout <= 0 {
		opts.ReadyTimeout = 120
	}
	tok := opts.Token
	if tok == "" {
		tok = wafipc.GenToken()
	}
	return &Supervisor{
		opts:    opts,
		token:   tok,
		workers: make(map[int]*workerState),
		readyCh: make(map[int]chan struct{}),
		done:    make(chan struct{}),
	}
}

// CtrlAddr 返回控制通道地址（监听后有效）。
func (s *Supervisor) CtrlAddr() string { return s.ctrlAddr }

// Run 启动监护器主循环（阻塞，直到 Shutdown）。
func (s *Supervisor) Run() error {
	// 自身重启认领（Phase 3.5）：读取上次持久化状态，复用控制端口 + token，
	// 让上次遗留、仍存活的 Worker(孤儿，例如 Supervisor 崩溃被服务管理器拉起的场景)能用旧 token 重连回来。
	prev := loadPrevStateFile(s.opts.DataDir)
	listenPort := s.opts.CtrlPort
	if prev != nil {
		if prev.Token != "" {
			s.token = prev.Token // 复用旧 token，孤儿才能通过鉴权重连
		}
		if p := portOf(prev.CtrlAddr); p > 0 {
			listenPort = p // 复用旧控制端口，孤儿的重连目标地址不变
		}
	}

	ln, err := wafipc.Listen(listenPort)
	if err != nil {
		if listenPort != 0 {
			// 复用端口失败(极少数：被他人占用) → 回退随机端口。孤儿将无法重连，
			// 此时不冒险按 PID 硬杀(防 PID 复用误杀)，仅记录，后续按普通启动处理。
			zlog.Warn("[Supervisor] 复用控制端口 " + strconv.Itoa(listenPort) + " 失败(" + err.Error() + ")，回退随机端口；遗留孤儿可能无法收编")
			ln, err = wafipc.Listen(0)
		}
		if err != nil {
			return err
		}
	}
	s.ln = ln
	s.ctrlAddr = ln.Addr().String()
	zlog.Info("[Supervisor] 控制通道监听于 " + s.ctrlAddr)
	s.writeState()

	go s.acceptLoop()

	// 若上次遗留存活 Worker(孤儿)，零停机收编为受管新 Worker；否则正常拉起首个 Worker。
	if prev != nil && s.adoptOrphans(prev) {
		zlog.Info("[Supervisor] 已完成遗留 Worker 收编，跳过拉起首个 Worker")
	} else {
		if _, err := s.spawn(false); err != nil {
			zlog.Error("[Supervisor] 拉起首个 Worker 失败: " + err.Error())
			return err
		}
	}

	<-s.done
	return nil
}

// Shutdown 优雅停止：令所有 Worker 退出，停止监护。
func (s *Supervisor) Shutdown() {
	s.mu.Lock()
	if s.shuttingDown {
		s.mu.Unlock()
		return
	}
	s.shuttingDown = true
	ws := make([]*workerState, 0, len(s.workers))
	for _, w := range s.workers {
		ws = append(ws, w)
	}
	s.mu.Unlock()

	zlog.Info("[Supervisor] 收到停止指令，通知所有 Worker 优雅退出...")
	for _, w := range ws {
		w.send(wafipc.Message{Type: wafipc.MsgShutdown})
	}
	// 给 Worker 一点时间排空退出
	deadline := time.Now().Add(time.Duration(s.opts.DrainTimeout+5) * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := len(s.workers)
		s.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
	close(s.done)
}

// acceptLoop 接受 Worker 的控制连接。
func (s *Supervisor) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			s.mu.Lock()
			down := s.shuttingDown
			s.mu.Unlock()
			if down {
				return
			}
			zlog.Warn("[Supervisor] 控制通道 Accept 出错: " + err.Error())
			time.Sleep(200 * time.Millisecond)
			continue
		}
		go s.handleConn(wafipc.NewConn(conn))
	}
}

func (s *Supervisor) handleConn(c *wafipc.Conn) {
	// 首条消息必须通过 token 校验
	first, err := c.Recv()
	if err != nil {
		_ = c.Close()
		return
	}
	if first.Token != s.token {
		zlog.Warn("[Supervisor] 拒绝非法控制连接(token 校验失败) from " + c.RemoteAddr().String())
		_ = c.Close()
		return
	}
	// 运维/测试触发：手动滚动重启（零停机换 Worker），无需注册为 Worker
	if first.Type == wafipc.MsgTriggerUpgrade {
		zlog.Info("[Supervisor] 收到手动滚动重启(TRIGGER_UPGRADE)请求 from " + c.RemoteAddr().String())
		_ = c.Send(wafipc.Message{Type: wafipc.MsgAck})
		_ = c.Close()
		go s.doUpgrade()
		return
	}
	if first.Type != wafipc.MsgHello {
		_ = c.Close()
		return
	}
	if first.ProtoVer != wafipc.ProtoVersion {
		zlog.Warn("[Supervisor] Worker 协议版本不兼容(本端=" + strconv.Itoa(wafipc.ProtoVersion) +
			" Worker=" + strconv.Itoa(first.ProtoVer) + ")，将令其退出并由全量重启兜底")
		c.Send(wafipc.Message{Type: wafipc.MsgShutdown})
		_ = c.Close()
		return
	}

	pid := first.PID
	s.mu.Lock()
	w := s.workers[pid]
	if w == nil {
		// 进程已 spawn 但尚未登记（理论上 spawn 时已登记），兜底创建
		w = &workerState{pid: pid, state: "starting"}
		s.workers[pid] = w
	}
	w.conn = c
	w.version = first.Version
	w.beats = time.Now()
	s.mu.Unlock()

	zlog.Info("[Supervisor] Worker 已连接 pid=" + strconv.Itoa(pid) + " version=" + first.Version)
	s.writeState()

	for {
		m, err := c.Recv()
		if err != nil {
			s.mu.Lock()
			if w.conn == c {
				w.conn = nil
			}
			s.mu.Unlock()
			return
		}
		s.onWorkerMsg(w, m)
	}
}

func (s *Supervisor) onWorkerMsg(w *workerState, m wafipc.Message) {
	switch m.Type {
	case wafipc.MsgReady:
		s.mu.Lock()
		w.state = "active-candidate"
		s.mu.Unlock()
		zlog.Info("[Supervisor] Worker pid=" + strconv.Itoa(w.pid) + " 上报 READY")
		s.signalReady(w.pid)
	case wafipc.MsgHeartbeat:
		s.mu.Lock()
		w.beats = time.Now()
		w.conns = m.Active
		s.mu.Unlock()
	case wafipc.MsgDraining:
		zlog.Info("[Supervisor] Worker pid=" + strconv.Itoa(w.pid) + " 排空中，剩余连接=" + strconv.FormatInt(m.Remaining, 10))
	case wafipc.MsgGone:
		zlog.Info("[Supervisor] Worker pid=" + strconv.Itoa(w.pid) + " 已完成排空，即将退出")
	case wafipc.MsgRequestUpgrade:
		go s.doUpgrade()
	}
}

// spawn 拉起一个 Worker 子进程。takeover=true 表示升级接管(与旧 Worker 并存)。
func (s *Supervisor) spawn(takeover bool) (int, error) {
	args := []string{"--worker", "--ctrl-addr=" + s.ctrlAddr, "--token=" + s.token}
	if takeover {
		args = append(args, "--takeover")
	}
	cmd := exec.Command(s.opts.ExePath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	w := &workerState{pid: pid, proc: cmd.Process, state: "starting", takeover: takeover, beats: time.Now()}
	s.mu.Lock()
	s.workers[pid] = w
	if !takeover && s.activePID == 0 {
		s.activePID = pid // 首个 worker 乐观置为 active
	}
	s.mu.Unlock()
	zlog.Info("[Supervisor] 已拉起 Worker pid=" + strconv.Itoa(pid) + " takeover=" + strconv.FormatBool(takeover))
	go s.monitor(w)
	return pid, nil
}

// monitor 监护单个 Worker 进程，退出后按需自愈。
func (s *Supervisor) monitor(w *workerState) {
	if w.proc == nil {
		return
	}
	state, _ := w.proc.Wait()
	exitInfo := ""
	exitCode := 0
	if state != nil {
		exitInfo = state.String()
		exitCode = state.ExitCode()
	}

	s.mu.Lock()
	planned := w.state == "draining"
	wasActive := w.pid == s.activePID
	delete(s.workers, w.pid)
	down := s.shuttingDown
	s.mu.Unlock()
	s.writeState()

	zlog.Info("[Supervisor] Worker pid=" + strconv.Itoa(w.pid) + " 退出(" + exitInfo + ") code=" + strconv.Itoa(exitCode) + " planned=" + strconv.FormatBool(planned))

	// 仅在“异常退出(非 0 退出码)”时自愈重拉。
	// 优雅退出(0)——如 DRAIN/SHUTDOWN/前台 Ctrl+C 的 os.Exit(0)——不重拉，
	// 避免停止过程中把刚优雅退出的 Worker 误判为崩溃而重启，导致残留孤儿 Worker、终端卡住。
	if down || planned || !wasActive || exitCode == 0 {
		return
	}

	// 活跃 Worker 意外退出 → 崩溃自愈
	s.handleCrashRespawn()
}

// upgradeProbationWindow 升级观察期：升级切到新版本后，仅在此时间窗内的连续崩溃才判为坏版本并回滚二进制；
// 超出该窗口的崩溃视为环境/配置问题，只重拉、不回滚，避免把运行已久的好版本误降级。
const upgradeProbationWindow = 5 * time.Minute

// handleCrashRespawn 活跃 Worker 异常退出后的自愈：指数退避重拉；升级观察期内多次崩溃判为坏版本并回滚。
func (s *Supervisor) handleCrashRespawn() {
	s.mu.Lock()
	now := time.Now()
	// 仅保留最近 60s 的崩溃记录
	kept := s.crashTimes[:0]
	for _, t := range s.crashTimes {
		if now.Sub(t) < 60*time.Second {
			kept = append(kept, t)
		}
	}
	s.crashTimes = append(kept, now)
	crashes := len(s.crashTimes)
	down := s.shuttingDown
	// 仅当处于"升级观察期"内（刚切到新版本不久）才把连续崩溃判为坏版本并回滚二进制。
	// 否则（日常环境/配置问题导致的崩溃、或已是回滚后的好版本）只重拉、不动二进制，避免把好版本误降级。
	inProbation := !s.lastUpgradeAt.IsZero() && now.Sub(s.lastUpgradeAt) < upgradeProbationWindow
	s.activePID = 0
	s.mu.Unlock()

	if down {
		return
	}
	if crashes >= 3 {
		if inProbation {
			zlog.Error("[Supervisor] Worker 在 60s 内崩溃 " + strconv.Itoa(crashes) + " 次，且处于升级观察期，判为坏版本，触发二进制回滚")
			s.rollbackBinary()
			// 回滚后清空崩溃计数与观察期：给回滚后的好版本机会，且其自身崩溃不再触发二次回滚
			s.mu.Lock()
			s.crashTimes = nil
			s.lastUpgradeAt = time.Time{}
			s.mu.Unlock()
		} else {
			zlog.Error("[Supervisor] Worker 在 60s 内崩溃 " + strconv.Itoa(crashes) + " 次，但不在升级观察期，按环境/配置问题处理：仅重拉、不回滚二进制（请人工排查崩溃原因）")
		}
	}
	// 指数退避（最多 ~5s）
	backoff := time.Duration(crashes) * time.Second
	if backoff > 5*time.Second {
		backoff = 5 * time.Second
	}
	time.Sleep(backoff)

	s.mu.Lock()
	down = s.shuttingDown
	s.mu.Unlock()
	if down {
		return
	}
	zlog.Info("[Supervisor] 自愈：重新拉起 Worker")
	if _, err := s.spawn(false); err != nil {
		zlog.Error("[Supervisor] 自愈重拉 Worker 失败: " + err.Error())
	}
}

// doUpgrade 编排滚动升级：起新 takeover Worker → 等其 READY → 令老 Worker 排空退出。
func (s *Supervisor) doUpgrade() {
	s.mu.Lock()
	if s.upgrading {
		s.mu.Unlock()
		zlog.Warn("[Supervisor] 已有升级在进行中，忽略本次请求")
		return
	}
	s.upgrading = true
	oldPID := s.activePID
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.upgrading = false
		s.mu.Unlock()
	}()

	zlog.Info("[Supervisor] 开始滚动升级，旧 Worker pid=" + strconv.Itoa(oldPID))

	newPID, err := s.spawn(true)
	if err != nil {
		zlog.Error("[Supervisor] 升级：拉起新 Worker 失败: " + err.Error())
		return
	}

	if !s.waitReady(newPID, time.Duration(s.opts.ReadyTimeout)*time.Second) {
		zlog.Error("[Supervisor] 升级：新 Worker pid=" + strconv.Itoa(newPID) + " 未在超时内就绪，回滚（保留旧 Worker）")
		s.killWorker(newPID)
		s.rollbackBinary()
		return
	}

	// 新 Worker 就绪 → 切为 active，令旧 Worker 排空退出
	s.mu.Lock()
	s.activePID = newPID
	// 记录本次升级切换时刻：从此进入"升级观察期"，期内新版本若连续崩溃才判坏版本并回滚二进制。
	s.lastUpgradeAt = time.Now()
	if nw := s.workers[newPID]; nw != nil {
		nw.state = "active"
	}
	old := s.workers[oldPID]
	if old != nil {
		old.state = "draining"
	}
	s.mu.Unlock()
	s.writeState()

	if old != nil {
		zlog.Info("[Supervisor] 新 Worker 就绪，令旧 Worker pid=" + strconv.Itoa(oldPID) + " 优雅排空退出")
		old.send(wafipc.Message{Type: wafipc.MsgDrain, Timeout: s.opts.DrainTimeout})
		// 必须等旧 Worker 进程"真正退出"后再让新 Worker 接管独占单例（应用/隧道/cron）。
		// 旧 Worker 的 Graceful = HTTP 排空(≤DrainTimeout) + 停止应用/隧道(各自的停止超时) + 杂项，
		// 可能远超 DrainTimeout，这里给足余量（poll 到旧 Worker 退出即提前返回，不会白等）。
		// 若过早 ACTIVATE，新应用会因旧应用端口未释放而绑定失败崩溃。
		s.waitWorkerGone(oldPID, time.Duration(2*s.opts.DrainTimeout+120)*time.Second)
		// 旧 Worker 退出后再留一点点余量，确保其应用进程树占用的端口被 OS 完全释放
		time.Sleep(1 * time.Second)
	}
	if nw := s.getWorker(newPID); nw != nil {
		zlog.Info("[Supervisor] 旧 Worker 已退出，通知新 Worker pid=" + strconv.Itoa(newPID) + " 接管独占单例(应用/隧道/cron)")
		nw.send(wafipc.Message{Type: wafipc.MsgActivate})
	}
	zlog.Info("[Supervisor] 滚动升级完成，active Worker pid=" + strconv.Itoa(newPID))
}

// adoptOrphans 处理 Supervisor 自身重启后遗留的、仍存活的 Worker(孤儿)。
//
// 典型场景：Supervisor 崩溃被服务管理器(SCM/systemd)拉起，而子 Worker 未被连带杀(Windows 无 Job Object)，
// 成为孤儿——它仍在转发业务、并持续重连控制通道。若不处理，新 Supervisor 会另起一个新 Worker，
// 造成双 Worker 并存 + 独占单例(应用/隧道/cron)重复运行冲突。
//
// 处理方式(复用升级编排，近零中断)：起一个受管的新 Worker(takeover，REUSEPORT 与孤儿并存、跳过 :26666 探测)，
// 就绪后令"重连且 token 鉴权通过"的孤儿优雅 DRAIN 退出，再 ACTIVATE 新 Worker 接管单例。
//
// 安全红线：只对"重连并通过 token 校验"的孤儿发 DRAIN(它自行 os.Exit)，**绝不按 PID 硬杀任何进程**——
// 防止 state 文件里的 PID 在 Supervisor 重启间隙被系统复用到无关进程而误杀。未重连的候选仅记录告警、跳过。
//
// 返回 true 表示已通过收编完成首个 Worker(调用方不再 spawn)。
func (s *Supervisor) adoptOrphans(prev *stateFile) bool {
	self := os.Getpid()
	var candidates []int
	for _, pid := range prev.PIDs {
		if pid > 0 && pid != self && isProcessAlive(pid) {
			candidates = append(candidates, pid)
		}
	}
	if len(candidates) == 0 {
		return false
	}
	zlog.Warn("[Supervisor] 检测到上次遗留的存活 Worker(孤儿) " + fmt.Sprint(candidates) + "，将零停机收编为受管新 Worker")

	// 预登记候选孤儿，等其用旧 token 重连回控制通道(loop 每 2s 重连，重连即证明确属本系统的 Worker)
	for _, pid := range candidates {
		s.mu.Lock()
		if s.workers[pid] == nil {
			s.workers[pid] = &workerState{pid: pid, state: "orphan", beats: time.Now()}
		}
		s.mu.Unlock()
	}

	// 起受管新 Worker(takeover：与孤儿 REUSEPORT 并存、跳过 :26666 单实例探测、延迟独占单例到 ACTIVATE)
	newPID, err := s.spawn(true)
	if err != nil {
		zlog.Error("[Supervisor] 收编：拉起新 Worker 失败(" + err.Error() + ")，改走普通启动")
		for _, pid := range candidates {
			s.mu.Lock()
			delete(s.workers, pid)
			s.mu.Unlock()
		}
		return false
	}

	if !s.waitReady(newPID, time.Duration(s.opts.ReadyTimeout)*time.Second) {
		// 新 Worker 没就绪 → 杀新；孤儿仍在转发业务(零中断)，留待下次升级/重启再收编。
		zlog.Error("[Supervisor] 收编：新 Worker pid=" + strconv.Itoa(newPID) + " 未就绪，保留孤儿继续服务(业务不中断)")
		s.killWorker(newPID)
		s.mu.Lock()
		delete(s.workers, newPID)
		s.mu.Unlock()
		return true // 返回 true 避免再 spawn 普通 Worker 造成重复
	}

	// 新 Worker 就绪 → 切为 active
	s.mu.Lock()
	s.activePID = newPID
	s.lastUpgradeAt = time.Now()
	if nw := s.workers[newPID]; nw != nil {
		nw.state = "active"
	}
	s.mu.Unlock()
	s.writeState()

	// 给候选孤儿一点时间重连(其 loop 每 2s 重连一次)，便于走优雅 DRAIN
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if s.allConnected(candidates) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// 只收尾"已重连(token 通过)"的孤儿：发 DRAIN 令其优雅退出；未重连的仅告警、跳过(不硬杀)
	var confirmed []int
	for _, pid := range candidates {
		w := s.getWorker(pid)
		if w != nil && w.conn != nil {
			confirmed = append(confirmed, pid)
			s.mu.Lock()
			w.state = "draining"
			s.mu.Unlock()
			zlog.Info("[Supervisor] 令孤儿 Worker pid=" + strconv.Itoa(pid) + " 优雅排空退出")
			w.send(wafipc.Message{Type: wafipc.MsgDrain, Timeout: s.opts.DrainTimeout})
		} else {
			zlog.Warn("[Supervisor] 候选孤儿 pid=" + strconv.Itoa(pid) + " 未重连(可能 PID 已复用或进程卡死)，为安全不硬杀、跳过；如确为残留请人工确认")
			s.mu.Lock()
			delete(s.workers, pid)
			s.mu.Unlock()
		}
	}

	if len(confirmed) > 0 {
		s.waitPIDsGone(confirmed, time.Duration(2*s.opts.DrainTimeout+120)*time.Second)
		time.Sleep(1 * time.Second) // 余量，确保孤儿应用进程树占用的端口被 OS 完全释放
	}

	// ACTIVATE 新 Worker 接管独占单例(应用/隧道/cron)
	if nw := s.getWorker(newPID); nw != nil {
		zlog.Info("[Supervisor] 孤儿已收尾，通知新 Worker pid=" + strconv.Itoa(newPID) + " 接管独占单例(应用/隧道/cron)")
		nw.send(wafipc.Message{Type: wafipc.MsgActivate})
	}
	zlog.Info("[Supervisor] 遗留 Worker 收编完成，active Worker pid=" + strconv.Itoa(newPID))
	return true
}

// allConnected 判断给定 PID 是否都已建立控制连接（线程安全）。
func (s *Supervisor) allConnected(pids []int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pid := range pids {
		w := s.workers[pid]
		if w == nil || w.conn == nil {
			return false
		}
	}
	return true
}

// waitPIDsGone 轮询等待一组 PID 全部退出，退出的从注册表清理；或超时返回。
func (s *Supervisor) waitPIDsGone(pids []int, timeout time.Duration) {
	dl := time.Now().Add(timeout)
	for time.Now().Before(dl) {
		allGone := true
		for _, pid := range pids {
			if isProcessAlive(pid) {
				allGone = false
			} else {
				s.mu.Lock()
				delete(s.workers, pid)
				s.mu.Unlock()
			}
		}
		if allGone {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	zlog.Warn("[Supervisor] 等待孤儿 Worker 退出超时，仍继续后续接管")
}

// getWorker 按 pid 取 Worker（线程安全）。
func (s *Supervisor) getWorker(pid int) *workerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.workers[pid]
}

// waitWorkerGone 轮询等待指定 Worker 从注册表移除（即进程已退出），或超时返回。
func (s *Supervisor) waitWorkerGone(pid int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		_, ok := s.workers[pid]
		s.mu.Unlock()
		if !ok {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	zlog.Warn("[Supervisor] 等待旧 Worker pid=" + strconv.Itoa(pid) + " 退出超时，仍继续通知新 Worker 接管")
}

// killWorker 强制结束指定 Worker（升级失败时清理新 Worker）。
func (s *Supervisor) killWorker(pid int) {
	s.mu.Lock()
	w := s.workers[pid]
	s.mu.Unlock()
	if w == nil {
		return
	}
	w.send(wafipc.Message{Type: wafipc.MsgShutdown})
	time.Sleep(500 * time.Millisecond)
	if w.proc != nil {
		_ = w.proc.Kill()
	}
}

func (s *Supervisor) waitReady(pid int, timeout time.Duration) bool {
	s.readyMu.Lock()
	ch, ok := s.readyCh[pid]
	if !ok {
		ch = make(chan struct{}, 1)
		s.readyCh[pid] = ch
	}
	s.readyMu.Unlock()

	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (s *Supervisor) signalReady(pid int) {
	s.readyMu.Lock()
	ch, ok := s.readyCh[pid]
	if !ok {
		ch = make(chan struct{}, 1)
		s.readyCh[pid] = ch
	}
	s.readyMu.Unlock()
	select {
	case ch <- struct{}{}:
	default:
	}
}

// rollbackBinary 升级失败/坏版本时回滚二进制：将磁盘上的可执行文件还原为上一个备份版本。
//
// 调用方约定（本函数只负责"换二进制"，不负责"拉 Worker"）：
//   - 升级就绪失败路径（doUpgrade）：旧 Worker 仍在服务，回滚后无需重拉，下次升级/重启即用还原后的版本；
//   - 崩溃自愈路径（handleCrashRespawn）：回滚后由其末尾的 spawn(false) 以还原后的好版本拉起干净 Worker。
//
// 备份由正常升级流程在覆盖前自动生成（wafupdate.BackupFile → data/backups_bin，按时间倒序，最新在前），
// 故 RollbackExecutable("") 还原的即"被坏版本覆盖掉的那个好版本"。回滚失败不影响业务：旧 Worker 仍在服务。
func (s *Supervisor) rollbackBinary() {
	target := ""
	if list, err := wafupdate.ListBackups(); err == nil && len(list) > 0 {
		target = list[0].Version
	}
	if err := wafupdate.RollbackExecutable(""); err != nil {
		zlog.Error("[Supervisor] 二进制回滚失败: " + err.Error() + "（旧 Worker 仍在服务，业务未中断；请人工检查升级包/备份）")
		return
	}
	zlog.Warn("[Supervisor] 二进制已回滚到上一个备份版本 " + target + "，后续将以该版本拉起 Worker（业务全程未中断）")
}

// stateFile 持久化的监护状态（供 Supervisor 自升级后重连认领，Phase 3.5）。
type stateFile struct {
	CtrlAddr  string   `json:"ctrl_addr"`
	Token     string   `json:"token"`
	ActivePID int      `json:"active_pid"`
	PIDs      []int    `json:"pids"`
	Versions  []string `json:"versions"`
	UpdatedAt string   `json:"updated_at"`
}

func (s *Supervisor) writeState() {
	if s.opts.DataDir == "" {
		return
	}
	s.mu.Lock()
	st := stateFile{
		CtrlAddr:  s.ctrlAddr,
		Token:     s.token,
		ActivePID: s.activePID,
		UpdatedAt: time.Now().Format(time.RFC3339),
	}
	for pid, w := range s.workers {
		st.PIDs = append(st.PIDs, pid)
		st.Versions = append(st.Versions, w.version)
	}
	s.mu.Unlock()

	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	path := filepath.Join(s.opts.DataDir, "supervisor.state")
	_ = os.WriteFile(path, b, 0600)
}

// loadPrevStateFile 读取上次持久化的完整监护状态（供自身重启后复用端口/token 并收编孤儿）。失败返回 nil。
func loadPrevStateFile(dataDir string) *stateFile {
	if dataDir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "supervisor.state"))
	if err != nil {
		return nil
	}
	var st stateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return nil
	}
	return &st
}

// portOf 从 "host:port" 提取端口；解析失败返回 0。
func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// ReadState 读取持久化的监护状态（ctrlAddr/token），供外部命令(如 rolling-restart)连接 Supervisor。
func ReadState(dataDir string) (ctrlAddr, token string, err error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "supervisor.state"))
	if err != nil {
		return "", "", err
	}
	var st stateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return "", "", err
	}
	return st.CtrlAddr, st.Token, nil
}

// TriggerUpgrade 连接到运行中的 Supervisor，触发一次零停机滚动重启（换 Worker）。
// 用于测试或运维 reload：无需真实新版本，Supervisor 会起新 Worker(takeover)→就绪→旧 Worker 排空退出。
func TriggerUpgrade(dataDir string) error {
	ctrlAddr, token, err := ReadState(dataDir)
	if err != nil {
		return fmt.Errorf("读取 supervisor.state 失败(Supervisor 是否在运行?): %w", err)
	}
	conn, err := wafipc.Dial(ctrlAddr)
	if err != nil {
		return fmt.Errorf("连接 Supervisor 控制通道 %s 失败: %w", ctrlAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Send(wafipc.Message{Type: wafipc.MsgTriggerUpgrade, Token: token}); err != nil {
		return err
	}
	m, err := conn.Recv()
	if err != nil {
		return fmt.Errorf("等待 Supervisor 应答失败: %w", err)
	}
	if m.Type != wafipc.MsgAck {
		return fmt.Errorf("Supervisor 应答异常: %s", m.Type)
	}
	return nil
}
