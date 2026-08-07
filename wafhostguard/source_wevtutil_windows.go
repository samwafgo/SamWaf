//go:build windows

package wafhostguard

import (
	"SamWaf/common/wafexec"
	"SamWaf/common/zlog"
	"context"
	"encoding/xml"
	"os/exec"
	"strings"
	"time"
)

// wevtapi 绑定失败(精简版系统、DLL 缺函数、频道无权限)时的降级通道：
// 定期调 wevtutil 查最近的事件，用 EventRecordID 做书签去重。
//
// 比订阅慢(默认 5 秒一轮)，但零绑定风险。宁可慢一点也不能整个功能在
// 某些系统上直接不可用。

const (
	// wevtutilInterval 轮询间隔
	wevtutilInterval = 5 * time.Second
	// wevtutilBatch 单次最多取多少条。5 秒内 4625 超过这个数说明正在被猛攻，
	// 丢掉更早的那些也无所谓——阈值早就触发了。
	wevtutilBatch = 200
	// wevtutilTimeout 单次命令超时
	wevtutilTimeout = 15 * time.Second
)

// runWevtutil 降级模式主循环
func (s *winEventSource) runWevtutil(ctx context.Context, out chan<- LoginFailEvent) error {
	var lastSecurityID uint64
	var lastRdpID uint64

	ticker := time.NewTicker(wevtutilInterval)
	defer ticker.Stop()

	// 首轮先把书签推到当前最新，避免把历史事件当成刚发生的
	lastSecurityID = latestRecordID(ctx, securityChannel, security4625Qry)
	lastRdpID = latestRecordID(ctx, rdpCoreChannel, rdpCoreQry)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		// 先收 RdpCoreTS，让环形缓冲里先有 IP，再处理 4625 才补得上
		if xmls, maxID := queryEvents(ctx, rdpCoreChannel, rdpCoreQry, lastRdpID); len(xmls) > 0 {
			for _, x := range xmls {
				if ip, at, ok := ParseRdpCoreTSIP(x, time.Now()); ok {
					s.ring.add(ip, at)
				}
			}
			if maxID > lastRdpID {
				lastRdpID = maxID
			}
		}

		xmls, maxID := queryEvents(ctx, securityChannel, security4625Qry, lastSecurityID)
		for _, x := range xmls {
			s.handle4625(ctx, x, out)
		}
		if maxID > lastSecurityID {
			lastSecurityID = maxID
		}
	}
}

// queryEvents 查 afterID 之后的新事件，返回 XML 列表与本批最大 RecordID。
// 结果按时间倒序返回，这里翻转成正序处理，保证 4625 的处理顺序与发生顺序一致。
func queryEvents(ctx context.Context, channel, query string, afterID uint64) ([]string, uint64) {
	raw := runWevtutilQuery(ctx, channel, query, wevtutilBatch)
	if len(raw) == 0 {
		return nil, afterID
	}

	maxID := afterID
	out := make([]string, 0, len(raw))
	// raw 是倒序(最新在前)，倒着遍历得到正序
	for i := len(raw) - 1; i >= 0; i-- {
		id := recordIDOf(raw[i])
		if id <= afterID {
			continue
		}
		if id > maxID {
			maxID = id
		}
		out = append(out, raw[i])
	}
	return out, maxID
}

// latestRecordID 取该频道当前最新一条的 RecordID，用作初始书签
func latestRecordID(ctx context.Context, channel, query string) uint64 {
	raw := runWevtutilQuery(ctx, channel, query, 1)
	if len(raw) == 0 {
		return 0
	}
	return recordIDOf(raw[0])
}

// runWevtutil 执行查询并把输出拆成一条条 XML
func runWevtutilQuery(ctx context.Context, channel, query string, count int) []string {
	cctx, cancel := context.WithTimeout(ctx, wevtutilTimeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, "wevtutil", "qe", channel,
		"/q:"+query,
		"/f:RenderedXml",
		"/c:"+itoa(count),
		"/rd:true") // 倒序，最新的在前
	out, err := wafexec.FixStdin(cmd).Output()
	if err != nil {
		if cctx.Err() == nil {
			zlog.Debug("[主机登录防护] wevtutil 查询失败", "channel", channel, "error", err.Error())
		}
		return nil
	}
	return splitEventXML(string(out))
}

// splitEventXML 把 wevtutil 连续输出的多个 <Event>...</Event> 拆开。
// wevtutil 不输出根元素，多条事件是首尾相接的，不能整体 Unmarshal。
func splitEventXML(s string) []string {
	var out []string
	for {
		start := strings.Index(s, "<Event ")
		if start < 0 {
			start = strings.Index(s, "<Event>")
		}
		if start < 0 {
			return out
		}
		end := strings.Index(s[start:], "</Event>")
		if end < 0 {
			return out
		}
		end += start + len("</Event>")
		out = append(out, s[start:end])
		s = s[end:]
	}
}

// recordIDOf 抽 EventRecordID 用作书签
func recordIDOf(xmlStr string) uint64 {
	var e winEvent
	if err := xml.Unmarshal([]byte(xmlStr), &e); err != nil {
		return 0
	}
	return e.System.EventRecordID
}

func itoa(n int) string {
	if n <= 0 {
		return "1"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// newSources Windows 事件源装配：优先 wevtapi 订阅，不可用则降级 wevtutil 轮询
func newSources() ([]Source, string) {
	ok, reason, _ := checkLogCapability()
	if !ok {
		return nil, reason
	}

	src := &winEventSource{ring: newRDPIPRing()}
	if err := wevtAvailable(); err != nil {
		src.fallback = true
		zlog.Warn("[主机登录防护] wevtapi 不可用，已降级为 wevtutil 轮询(每5秒一次，实时性略差但功能不受影响)",
			"error", err.Error())
	}
	return []Source{src}, ""
}
