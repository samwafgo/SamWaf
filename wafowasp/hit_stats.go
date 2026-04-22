package wafowasp

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// RuleHitEntry 单条规则的命中统计（无锁计数器 + 一次性初始化的元数据）。
type RuleHitEntry struct {
	once         sync.Once // 保证 Message/Severity 只初始化一次
	Message      string
	Severity     string
	TotalHits    atomic.Int64
	BlockedHits  atomic.Int64
	DetectedHits atomic.Int64
	lastSeenNano atomic.Int64 // Unix nano
}

func (e *RuleHitEntry) initMeta(message, severity string) {
	e.once.Do(func() {
		e.Message = message
		e.Severity = severity
	})
}

// HitStatsTracker 全局规则命中统计，完全线程安全，热路径无互斥锁。
type HitStatsTracker struct {
	m sync.Map // key: int (ruleID) → *RuleHitEntry
}

// GlobalHitStats 全局单例，由 initowasp.go 热路径调用。
var GlobalHitStats = &HitStatsTracker{}

func (t *HitStatsTracker) entry(ruleID int, message, severity string) *RuleHitEntry {
	if v, ok := t.m.Load(ruleID); ok {
		e := v.(*RuleHitEntry)
		if message != "" {
			e.initMeta(message, severity)
		}
		return e
	}
	ne := &RuleHitEntry{}
	if message != "" {
		ne.Message = message
		ne.Severity = severity
	}
	actual, _ := t.m.LoadOrStore(ruleID, ne)
	e := actual.(*RuleHitEntry)
	if message != "" {
		e.initMeta(message, severity)
	}
	return e
}

// RecordBlocked 记录一次拦截命中（On 模式下 handleInterruption 调用）。
func (t *HitStatsTracker) RecordBlocked(ruleID int, message, severity string) {
	if ruleID <= 0 {
		return
	}
	e := t.entry(ruleID, message, severity)
	e.TotalHits.Add(1)
	e.BlockedHits.Add(1)
	e.lastSeenNano.Store(time.Now().UnixNano())
}

// RecordDetected 记录一次观察模式命中（DetectionOnly 下 logDetectionOnlyWouldBlock 调用）。
func (t *HitStatsTracker) RecordDetected(ruleID int, message, severity string) {
	if ruleID <= 0 {
		return
	}
	e := t.entry(ruleID, message, severity)
	e.TotalHits.Add(1)
	e.DetectedHits.Add(1)
	e.lastSeenNano.Store(time.Now().UnixNano())
}

// RuleHitStat 对外暴露的规则命中快照（JSON 序列化友好）。
type RuleHitStat struct {
	RuleID       int    `json:"rule_id"`
	Message      string `json:"message"`
	Severity     string `json:"severity"`
	TotalHits    int64  `json:"total_hits"`
	BlockedHits  int64  `json:"blocked_hits"`
	DetectedHits int64  `json:"detected_hits"`
	LastSeenAt   string `json:"last_seen_at"`
}

// TopN 返回按指定维度降序的前 n 条记录。
// mode: "blocked" / "detected" / 其他 → 按 total_hits 排序。
func (t *HitStatsTracker) TopN(n int, mode string) []RuleHitStat {
	if n <= 0 {
		n = 50
	}
	var out []RuleHitStat
	t.m.Range(func(k, v interface{}) bool {
		e := v.(*RuleHitEntry)
		nano := e.lastSeenNano.Load()
		lastSeen := ""
		if nano > 0 {
			lastSeen = time.Unix(0, nano).Format("2006-01-02 15:04:05")
		}
		out = append(out, RuleHitStat{
			RuleID:       k.(int),
			Message:      e.Message,
			Severity:     e.Severity,
			TotalHits:    e.TotalHits.Load(),
			BlockedHits:  e.BlockedHits.Load(),
			DetectedHits: e.DetectedHits.Load(),
			LastSeenAt:   lastSeen,
		})
		return true
	})

	sort.Slice(out, func(i, j int) bool {
		var ci, cj int64
		switch mode {
		case "blocked":
			ci, cj = out[i].BlockedHits, out[j].BlockedHits
		case "detected":
			ci, cj = out[i].DetectedHits, out[j].DetectedHits
		default:
			ci, cj = out[i].TotalHits, out[j].TotalHits
		}
		if ci != cj {
			return ci > cj
		}
		return out[i].RuleID < out[j].RuleID
	})

	if n > len(out) {
		n = len(out)
	}
	return out[:n]
}

// TotalRuleCount 返回当前有命中记录的规则数量。
func (t *HitStatsTracker) TotalRuleCount() int {
	count := 0
	t.m.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// Reset 清空所有命中计数（注意：内存释放由 GC 负责）。
func (t *HitStatsTracker) Reset() {
	t.m.Range(func(k, _ interface{}) bool {
		t.m.Delete(k)
		return true
	})
}
