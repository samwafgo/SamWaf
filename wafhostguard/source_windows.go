//go:build windows

package wafhostguard

import (
	"SamWaf/common/zlog"
	"context"
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

	// 等待信号的超时，同时决定了 Stop() 的最坏响应时间
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

	var wg sync.WaitGroup

	// RdpCoreTS 频道：只负责往环形缓冲里塞 IP。
	// 这个频道在 Win7 精简版或被禁用时打不开，属于"降级但不致命"——
	// 主频道的 4625 只要自带 IP 就照常工作。
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := s.subscribeLoop(ctx, rdpCoreChannel, rdpCoreQry, func(xmlStr string) {
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

	// Security 频道：主信号
	err := s.subscribeLoop(ctx, securityChannel, security4625Qry, func(xmlStr string) {
		s.handle4625(ctx, xmlStr, out)
	})

	wg.Wait()
	return err
}

// subscribeLoop 订阅一个频道并持续拉取，直到 ctx 取消
func (s *winEventSource) subscribeLoop(ctx context.Context, channel, query string, onEvent func(string)) error {
	signal, err := windows.CreateEvent(nil, 1 /*手动重置*/, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(signal)

	sub, err := evtSubscribe(signal, channel, query)
	if err != nil {
		return err
	}
	defer evtClose(sub)

	for {
		if ctx.Err() != nil {
			return nil
		}
		xmls, err := evtNextXML(sub, signal, wevtWaitMs)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			zlog.Debug("[主机登录防护] 读取Windows事件失败", "channel", channel, "error", err.Error())
			// 单次失败不退订，睡一下继续——事件日志服务偶发抖动很常见
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
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
