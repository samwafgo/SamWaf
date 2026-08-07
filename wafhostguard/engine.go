package wafhostguard

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// 引擎：把事件源、判定、处置串起来的地方，同时负责生命周期。
//
// **生命周期是这个模块的正确性要害**。SamWaf 是 Supervisor + Worker 双进程，
// 滚动升级时新旧 Worker 会并存最多 30 秒。如果采集器在 run() 里无条件启动，
// 这 30 秒内两个进程会同时 tail 同一份日志，同一条 Failed password 被计两次；
// 而缓存默认是进程内内存，两边计数器互相看不见，于是各自都以为"才 4 次"，
// 实际用户配的 8 次阈值被腰斩成 4 次，误封概率显著上升。
// 所以 Start() 只能挂在 activateSingletons()(Supervisor 确认旧 Worker 已退出后才触发)
// 和非 takeover 的首启路径上，见 cmd/samwaf/main.go。

// eventChanSize 事件通道缓冲。爆破高峰下每秒可能几十上百条，
// 留一千多的缓冲让消费端(要查库、要写库)有喘息空间。
const eventChanSize = 1024

// Engine 主机登录防护引擎
type Engine struct {
	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	events  chan LoginFailEvent

	// 运行态指标，供状态接口展示
	startedAt   time.Time
	sourceNames []string
	unavailable string // 非空表示当前环境采集不了，内容是可直接展示的中文原因
	lastEventAt atomic.Int64
	totalParsed atomic.Int64
	totalBanned atomic.Int64
	dropped     atomic.Int64
}

var engine = &Engine{}

// GetEngine 取引擎单例
func GetEngine() *Engine { return engine }

// dropEvent 记一次因通道满而丢弃的事件。
// 采集端宁可丢事件也不能阻塞——阻塞会让 fd 里的数据越积越多，
// 最后连"现在正在发生什么"都读不到了。
func dropEvent() { engine.dropped.Add(1) }

// Start 启动采集(幂等)。调用点见 cmd/samwaf/main.go 的两处。
func Start() { engine.Start() }

// Stop 停止采集(幂等)，等所有事件源退出后返回
func Stop() { engine.Stop() }

// Reload 配置变更后重新应用：开关 0→1 启动，1→0 停止
func Reload() {
	if global.GCONFIG_HOST_GUARD_ENABLED == 1 {
		engine.Start()
	} else {
		engine.Stop()
	}
}

// Start 启动引擎
func (e *Engine) Start() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return
	}

	if global.GCONFIG_HOST_GUARD_FORCE_DISABLE {
		zlog.Warn("[主机登录防护] 已被 conf/config.yml 的 security.host_guard_force_disable " +
			"或环境变量 SAMWAF_HOSTGUARD_DISABLE 强制关闭，不启动采集")
		return
	}
	if global.GCONFIG_HOST_GUARD_ENABLED != 1 {
		return
	}

	srcs, reason := newSources()
	if len(srcs) == 0 {
		e.unavailable = reason
		zlog.Warn("[主机登录防护] " + reason)
		return
	}
	e.unavailable = ""

	// 封禁范围要在重放之前设好：先建立起带端口限制的引用规则，
	// 再把地址灌进集合，中间不会出现"短暂按全端口封着"的窗口
	GetBanExecutor().ApplyPortScope()

	// 先把库里未过期的封禁重灌回系统防火墙：ipset 是内核内存态，机器重启就空了，
	// 不重放的话数据库里写着"正在封禁 200 个 IP"，实际一个都没生效
	if err := GetBanExecutor().ReplayOnStart(); err != nil {
		zlog.Warn("[主机登录防护] 重放历史封禁失败，新封禁不受影响", "error", err.Error())
	}

	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.events = make(chan LoginFailEvent, eventChanSize)
	e.running = true
	e.startedAt = time.Now()
	e.sourceNames = e.sourceNames[:0]

	for _, src := range srcs {
		e.sourceNames = append(e.sourceNames, src.Name())
		s := src
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer func() {
				// 事件源里任何 panic 都不该带崩整个 WAF
				if r := recover(); r != nil {
					zlog.Error("[主机登录防护] 事件源异常退出", "source", s.Name(), "panic", r)
				}
			}()
			if err := s.Run(ctx, e.events); err != nil && ctx.Err() == nil {
				zlog.Warn("[主机登录防护] 事件源停止", "source", s.Name(), "error", err.Error())
			}
		}()
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.consume(ctx)
	}()

	zlog.Info("[主机登录防护] 启动采集", "事件源", e.sourceNames,
		"模式", global.GCONFIG_HOST_GUARD_MODE,
		"窗口分钟", global.GCONFIG_HOST_GUARD_FIND_TIME,
		"阈值", global.GCONFIG_HOST_GUARD_MAX_RETRY)
}

// Stop 停止引擎。必须在 stopSamWaf 里、关库之前调用：
// 这里要把 Windows 待同步的脏集合刷下去，也要确保 fd / journalctl 子进程被释放，
// 否则新旧 Worker 交替时旧进程不放手，就会出现双读日志重复计数。
func (e *Engine) Stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	e.running = false
	cancel := e.cancel
	e.cancel = nil
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	// 等事件源退出，但不无限等：某个源卡死不能把整个进程的关闭流程拖住
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		zlog.Warn("[主机登录防护] 等待事件源退出超时，继续关闭")
	}

	// Windows 去抖路径下可能还有没落地的集合变更
	if err := GetBanExecutor().FlushPending(); err != nil {
		zlog.Warn("[主机登录防护] 关闭前同步封禁集合失败", "error", err.Error())
	}

	zlog.Info("[主机登录防护] 停止采集，已释放事件源", "数量", len(e.sourceNames))
}

// consume 事件消费主循环
func (e *Engine) consume(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-e.events:
			if !ok {
				return
			}
			e.handle(ev)
		}
	}
}

// handle 处理单条事件，任何 panic 都不影响后续事件
func (e *Engine) handle(ev LoginFailEvent) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error("[主机登录防护] 处理事件时异常", "ip", ev.IP, "panic", r)
		}
	}()

	e.totalParsed.Add(1)
	e.lastEventAt.Store(time.Now().Unix())

	res := Decide(ev)
	if res.Banned {
		e.totalBanned.Add(1)
	}
}

// Status 运行态快照
type Status struct {
	Running     bool       `json:"running"`
	Mode        string     `json:"mode"`
	Sources     []string   `json:"sources"`
	Unavailable string     `json:"unavailable"`
	StartedAt   int64      `json:"started_at"`
	LastEventAt int64      `json:"last_event_at"`
	TotalParsed int64      `json:"total_parsed"`
	TotalBanned int64      `json:"total_banned"`
	Dropped     int64      `json:"dropped"`
	BanCount    int        `json:"ban_count"`
	ExecMode    string     `json:"exec_mode"`
	LastSyncAt  int64      `json:"last_sync_at"`
	LastSyncMs  int64      `json:"last_sync_ms"`
	Capability  Capability `json:"capability"`
	SSHPorts    []int      `json:"ssh_ports"`
	RDPPorts    []int      `json:"rdp_ports"`
	// PortScopeSupported 当前平台是否支持"只封 SSH/RDP 端口"。
	// macOS 与逐条规则模式下为 false，前端据此禁用该选项。
	PortScopeSupported bool `json:"port_scope_supported"`
}

// GetStatus 汇总当前状态，供概览页展示
func GetStatus() Status {
	e := engine
	e.mu.Lock()
	running := e.running
	sources := append([]string(nil), e.sourceNames...)
	unavailable := e.unavailable
	startedAt := e.startedAt
	e.mu.Unlock()

	exec := GetBanExecutor()
	lastSyncAt, lastSyncMs := exec.LastSync()
	sshPorts, rdpPorts := GuardPorts()

	st := Status{
		Running:     running,
		Mode:        global.GCONFIG_HOST_GUARD_MODE,
		Sources:     sources,
		Unavailable: unavailable,
		LastEventAt: e.lastEventAt.Load(),
		TotalParsed: e.totalParsed.Load(),
		TotalBanned: e.totalBanned.Load(),
		Dropped:     e.dropped.Load(),
		BanCount:    exec.Count(),
		ExecMode:    exec.ExecMode(),
		LastSyncMs:  lastSyncMs,
		Capability:  GetCapability(),
		SSHPorts:    sshPorts,
		RDPPorts:    rdpPorts,

		PortScopeSupported: exec.SupportsPortScope(),
	}
	if !startedAt.IsZero() {
		st.StartedAt = startedAt.Unix()
	}
	if !lastSyncAt.IsZero() {
		st.LastSyncAt = lastSyncAt.Unix()
	}
	return st
}
