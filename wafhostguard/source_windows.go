//go:build windows

package wafhostguard

import (
	"SamWaf/common/zlog"
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// Windows 事件源。订阅两个频道：
//
//	Security                                            4625  登录失败(主信号)
//	Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational  131/140  客户端 IP
//
// 之所以要订第二个：4625 在"用户名不存在"等场景下 IpAddress 会是 "-"，
// 光凭它无法知道谁在爆破。RdpCoreTS 的 131/140 记录了 TCP 连接层的真实客户端地址，
// 按时间戳把两者关联起来就能补齐。
const (
	securityChannel = "Security"
	security4625Qry = "*[System[(EventID=4625)]]"

	rdpCoreChannel = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
	rdpCoreQry     = "*[System[(EventID=131 or EventID=140)]]"

	// 每一轮最多等信号量多久。等到了就立刻取，等不到也照样取一次
	// (见 evtNextXML 的注释：有些系统上这个信号量从不置位)。
	// 因此它同时是"信号量失效时的最大采集延迟"和 Stop() 的最坏响应时间。
	wevtWaitMs = 1000
)

// IP 关联参数
const (
	// rdpRingSize 环形缓冲容量。一次 RDP 爆破里 131/140 事件来得很密，
	// 256 条足够覆盖关联窗口，又不会占多少内存。
	rdpRingSize = 256
	// rdpRingTTL 缓冲里的条目多久算过期
	rdpRingTTL = 60 * time.Second
	// rdpMatchWindow 4625 与 RdpCoreTS 事件的时间容差
	rdpMatchWindow = 10 * time.Second
	// rdpPendingWait 4625 拿不到 IP 时最多等多久(RdpCoreTS 有时晚于 4625 落盘)
	rdpPendingWait = 3 * time.Second
	// rdpPendingRetry 等待期间的重试间隔
	rdpPendingRetry = 500 * time.Millisecond
)

// rdpIPEntry 一条客户端 IP 记录
type rdpIPEntry struct {
	ip string
	at time.Time
}

// rdpIPRing 时间有序的环形缓冲，用来给 4625 补源 IP
type rdpIPRing struct {
	mu      sync.Mutex
	entries []rdpIPEntry
}

func newRDPIPRing() *rdpIPRing {
	return &rdpIPRing{entries: make([]rdpIPEntry, 0, rdpRingSize)}
}

func (r *rdpIPRing) add(ip string, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, rdpIPEntry{ip: ip, at: at})
	if len(r.entries) > rdpRingSize {
		r.entries = r.entries[len(r.entries)-rdpRingSize:]
	}
}

// lookup 找时间上最接近 target 的一条 IP 记录。
//
// 命中的条目**不删除**：一次 RDP 连接会产生多条 4625(用户反复输错密码)，
// 它们共用同一个 TCP 连接的 131 事件，删掉的话第二条 4625 就补不到 IP 了。
func (r *rdpIPRing) lookup(target time.Time) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	best := ""
	var bestDiff time.Duration
	cutoff := time.Now().Add(-rdpRingTTL)

	for _, e := range r.entries {
		if e.at.Before(cutoff) {
			continue
		}
		diff := e.at.Sub(target)
		if diff < 0 {
			diff = -diff
		}
		if diff > rdpMatchWindow {
			continue
		}
		if best == "" || diff < bestDiff {
			best, bestDiff = e.ip, diff
		}
	}
	return best, best != ""
}

// winEventSource Windows 事件源
type winEventSource struct {
	ring     *rdpIPRing
	fallback bool // 是否已降级到 wevtutil 轮询
	// firstEvent 保证"采集链路正常"这条 Info 只打一次。
	// 排障时最想知道的就是"订阅到底有没有在投递"，而这个答案只需要说一次；
	// 每条都打会在爆破高峰把日志淹掉。
	firstEvent sync.Once
}

func (s *winEventSource) Name() string {
	if s.fallback {
		return "wevtutil(轮询)"
	}
	return "wevtapi(Security 4625 + RdpCoreTS 131/140)"
}

func (s *winEventSource) Run(ctx context.Context, out chan<- LoginFailEvent) error {
	if s.fallback {
		return s.runWevtutil(ctx, out)
	}

	err := s.runWevtapi(ctx, out)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return nil // 正常停止
	}

	// runWevtapi 没报错、外层也没停，只可能是看门狗判定订阅收不到事件。
	// 转轮询接管——宁可慢 5 秒，也不能让功能开着却一条都采不到。
	s.fallback = true
	zlog.Warn("[主机登录防护] 已切换到 wevtutil 轮询采集(每5秒一轮)，功能不受影响，仅实时性略有下降")
	return s.runWevtutil(ctx, out)
}

// runWevtapi 走 wevtapi 订阅。返回 nil 且外层 ctx 未取消，表示订阅不投递事件、
// 调用方应改用轮询。
func (s *winEventSource) runWevtapi(ctx context.Context, out chan<- LoginFailEvent) error {
	// 派生子 ctx：Security 订阅一旦失败，必须能把 RdpCoreTS 那个 goroutine 一起收掉。
	// 否则 wg.Wait() 会一直等下去(那个循环只在 ctx 取消时才退出)，Security 的错误
	// 永远返回不到调用方——界面就一直显示"运行中"，用户完全看不出采集其实从没生效。
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup

	// RdpCoreTS 频道：只负责往环形缓冲里塞 IP。
	// 这个频道在 Win7 精简版或被禁用时打不开，属于"降级但不致命"——
	// 主频道的 4625 只要自带 IP 就照常工作。
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := s.subscribeLoop(subCtx, rdpCoreChannel, rdpCoreQry, func(xmlStr string) {
			if ip, at, ok := ParseRdpCoreTSIP(xmlStr, time.Now()); ok {
				s.ring.add(ip, at)
			}
		})
		if err != nil && ctx.Err() == nil {
			zlog.Warn("[主机登录防护] RDP 详细日志频道不可用，无源IP的 4625 事件将被丢弃。"+
				"可在 事件查看器 → 应用程序和服务日志 → Microsoft → Windows → "+
				"RemoteDesktopServices-RdpCoreTS 中启用 Operational 日志", "error", err.Error())
		}
	}()

	// 看门狗：订阅"建得起来但不投递"是最难发现的故障——没有错误、没有事件，
	// 界面一切正常，实际完全没在保护。定期比对"我们收到的条数"与"系统里实际
	// 新增的 4625 条数"，只有在系统确实产生了新事件、而我们一条都没收到时才判定失效，
	// 避免把"服务器很安静"误判成故障。
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.watchDelivery(subCtx, cancel)
	}()

	// Security 频道：主信号
	err := s.subscribeLoop(subCtx, securityChannel, security4625Qry, func(xmlStr string) {
		noteRawEvent()
		s.firstEvent.Do(func() {
			zlog.Info("[主机登录防护] 已收到第一条 Windows 安全日志事件，采集链路正常")
		})
		s.handle4625(subCtx, xmlStr, out)
	})
	if err != nil && ctx.Err() == nil {
		// 用 Error 而不是 Warn：采集完全不生效，是"功能开着但没在保护你"，
		// 严重程度等同于没启用，必须让用户看见。
		reason := "订阅 Windows 安全日志(Security 频道)失败：" + err.Error() +
			"。请确认 SamWaf 以管理员身份运行，或已安装为系统服务(服务默认以 LocalSystem 运行)"
		zlog.Error("[主机登录防护] " + reason)
		noteSourceFailure(reason)
	}

	cancel() // 收掉 RdpCoreTS，避免 wg.Wait() 卡住
	wg.Wait()
	return err
}

// wevtapiProbeInterval 投递看门狗的检查间隔
const wevtapiProbeInterval = 60 * time.Second

// watchDelivery 监视 wevtapi 订阅到底有没有在投递事件，判定失效则取消订阅让上层转轮询。
//
// 判定条件刻意收得很紧：**必须同时满足**"我们一条都没收到"和"系统里确实新增了 4625"。
// 只看前者会把安静的服务器误判成故障，那样 wevtapi 就永远轮不上了。
func (s *winEventSource) watchDelivery(ctx context.Context, cancel context.CancelFunc) {
	startRaw := engine.rawReceived.Load()
	baseline := latestRecordID(ctx, securityChannel, security4625Qry)

	ticker := time.NewTicker(wevtapiProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if engine.rawReceived.Load() > startRaw {
			return // 订阅在正常工作，看门狗功成身退
		}
		cur := latestRecordID(ctx, securityChannel, security4625Qry)
		if cur <= baseline {
			continue // 这段时间系统本来就没有新的登录失败，说明不了问题
		}

		zlog.Warn("[主机登录防护] wevtapi 订阅已建立但收不到任何事件，"+
			"而系统安全日志中确实有新增的登录失败记录，判定该订阅在本机不可用",
			"系统新增记录号", cur, "订阅起始记录号", baseline)
		cancel()
		return
	}
}

// subscribeLoop 订阅一个频道并持续拉取，直到 ctx 取消
func (s *winEventSource) subscribeLoop(ctx context.Context, channel, query string, onEvent func(string)) error {
	signal, err := windows.CreateEvent(nil, 1 /*手动重置*/, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(signal)

	// 频道名与查询语句的 UTF16 缓冲区由本函数持有：订阅活多久，它们就得活多久。
	// 交给 evtSubscribe 内部创建的话，函数一返回就没人引用了，GC 可以直接回收。
	chBuf, err := windows.UTF16FromString(channel)
	if err != nil {
		return err
	}
	var qBuf []uint16
	var qPtr *uint16
	if query != "" {
		if qBuf, err = windows.UTF16FromString(query); err != nil {
			return err
		}
		qPtr = &qBuf[0]
	}
	defer runtime.KeepAlive(chBuf)
	defer runtime.KeepAlive(qBuf)

	sub, err := evtSubscribe(signal, &chBuf[0], qPtr)
	if err != nil {
		return fmt.Errorf("订阅频道 %s 失败: %w", channel, err)
	}
	defer evtClose(sub)

	// 订阅建立成功要留痕。没有这一行的话，"订阅失败"和"订阅成功但读不出事件"
	// 在日志里长得一模一样(都是什么都没有)，排障时无从下手。
	zlog.Info("[主机登录防护] 已建立事件订阅", "channel", channel)

	var readErrCount int64
	for {
		if ctx.Err() != nil {
			return nil
		}
		xmls, err := evtNextXML(sub, signal, wevtWaitMs)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// **第一次失败必须是可见级别**。这里原本只打 Debug，而服务器上
			// debug_enable 默认关着，于是"读取循环一直在报错空转"这种彻底失效的状态
			// 在日志里完全看不见——订阅成功、事件为零、一行日志都没有，无从判断。
			// 后续重复失败降回 Debug，避免每秒一条把日志刷爆。
			readErrCount++
			if readErrCount == 1 {
				zlog.Warn("[主机登录防护] 读取Windows事件失败，将持续重试。"+
					"若该错误反复出现，说明 wevtapi 订阅在本机不可用，事件将一直采集不到",
					"channel", channel, "error", err.Error())
			} else {
				zlog.Debug("[主机登录防护] 读取Windows事件失败", "channel", channel,
					"error", err.Error(), "累计失败次数", readErrCount)
			}
			// 单次失败不退订，睡一下继续——事件日志服务偶发抖动很常见
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		// 从失败中恢复了也说一声，否则用户只看到一条 Warn 会以为一直坏着
		if readErrCount > 0 {
			zlog.Info("[主机登录防护] 读取Windows事件已恢复", "channel", channel,
				"累计失败次数", readErrCount)
			readErrCount = 0
		}
		for _, x := range xmls {
			onEvent(x)
		}
	}
}

// handle4625 处理一条登录失败事件，必要时等 RdpCoreTS 补 IP
func (s *winEventSource) handle4625(ctx context.Context, xmlStr string, out chan<- LoginFailEvent) {
	ev, needResolve, ok := Parse4625(xmlStr, time.Now())
	if !ok {
		return
	}

	if needResolve {
		// RdpCoreTS 事件有时比 4625 晚落盘，给它一点时间
		deadline := time.Now().Add(rdpPendingWait)
		for {
			if ip, found := s.ring.lookup(ev.At); found {
				ev.IP = ip
				needResolve = false
				break
			}
			if time.Now().After(deadline) {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(rdpPendingRetry):
			}
		}
	}

	if needResolve || ev.IP == "" {
		// 补不到就丢。绝不用 WorkstationName 反查、也绝不拿"最近一个IP"顶上——
		// 那种兜底一旦猜错，被封的是一个完全无辜的地址。
		dropEvent()
		zlog.Debug("[主机登录防护] 4625 事件无可用源IP且无法关联 RdpCoreTS，已丢弃",
			"用户", ev.User, "登录类型", ev.LogonType)
		return
	}

	select {
	case out <- ev:
	case <-ctx.Done():
	default:
		dropEvent()
	}
}
