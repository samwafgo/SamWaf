package wafqueue

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"sync"
	"time"
)

// foldKey 折叠判定的维度：同一站点、同一来源IP、同一命中规则。
// 不含路径（加了等于没折叠：扫描/爆破每条路径都不同）。
type foldKey struct {
	hostCode string
	srcIP    string
	rule     string
}

// logFoldFilter 同类安全事件折叠：每个键在一个分钟窗口内只放行前 K 条落库，
// 其余不落明细。被折叠的事件在调用方仍参与统计、分析、CC、文件与 Kafka 出口，
// 所以面板计数与封禁行为不受影响，只减少明细落库行数。
//
// 只在日志消费协程里使用（单协程），但配置热加载会从别的协程改上限，
// 内部仍加锁。键数封顶：窗口内不同键超过上限后，新键一律放行（宁多记不漏记）。
type logFoldFilter struct {
	mu      sync.Mutex
	limit   int64
	counts  map[foldKey]int64
	window  int64 // 当前窗口 = Unix 时间戳整除 60
	maxKeys int
}

func newLogFoldFilter(maxKeys int) *logFoldFilter {
	return &logFoldFilter{limit: global.GCONFIG_LOG_FOLD_PER_MINUTE, counts: make(map[foldKey]int64), maxKeys: maxKeys}
}

// windowOf 取日志时间所在的分钟窗口。用日志自身时间而不是消费时刻：
// 攻击停止后积压的尾巴仍能归到它真实发生的分钟里，不会挤占新窗口的配额。
// 生产侧 UNIX_ADD_TIME 是毫秒（引擎入队时 UnixNano()/1e6），先换成秒再按分钟对齐。
func (f *logFoldFilter) windowOf(lg *innerbean.WebLog) int64 {
	if lg.UNIX_ADD_TIME > 0 {
		return lg.UNIX_ADD_TIME / 1000 / 60
	}
	return time.Now().Unix() / 60
}

// allow 返回这条日志是否落明细库。非安全事件（正常请求）一律放行；
// 折叠关闭（limit<=0）时一律放行。
func (f *logFoldFilter) allow(lg *innerbean.WebLog) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	// 上限同步必须先于 limit<=0 的早退：否则关过一次（0）之后 f.limit 永远停在 0，
	// 再开（>0）也永远不会被捡回来。
	if f.limit != global.GCONFIG_LOG_FOLD_PER_MINUTE {
		f.limit = global.GCONFIG_LOG_FOLD_PER_MINUTE
		f.counts = make(map[foldKey]int64, len(f.counts))
	}
	if f.limit <= 0 || !lg.IsSecurityEvent() {
		return true
	}
	key := foldKey{hostCode: lg.HOST_CODE, srcIP: lg.SRC_IP, rule: lg.RULE}

	w := f.windowOf(lg)
	if w != f.window {
		f.window = w
		f.counts = make(map[foldKey]int64, 1024)
	}
	n, seen := f.counts[key]
	if !seen && len(f.counts) >= f.maxKeys {
		return true // 键数封顶：不认识的键直接放行
	}
	f.counts[key] = n + 1
	return n < f.limit
}

// filterForStore 从一批日志里挑出「要落明细库」的部分，返回新切片
// （不复用入参数组的槽位：原数组还要给统计、分析、CC、文件与 Kafka 出口用全量）。
func (f *logFoldFilter) filterForStore(logs []*innerbean.WebLog) []*innerbean.WebLog {
	kept := make([]*innerbean.WebLog, 0, len(logs))
	for _, lg := range logs {
		if lg != nil && f.allow(lg) {
			kept = append(kept, lg)
		}
	}
	return kept
}
