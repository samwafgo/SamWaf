package wafipban

import (
	"SamWaf/cache"
	"SamWaf/cache/cachetest"
	"SamWaf/global"
	"SamWaf/innerbean"
	"testing"
)

// 双后端回归：内存后端原样存取 interface{}，JSON 类后端(RedisCache)经 JSON 编解码、
// Get 对结构体返回泛型 map。IP失败封禁的计数累计、阈值戳、列表判定在两种后端下
// 必须结果一致——否则换缓存类型会让规则计数静默归零、封禁永不触发。

// newTestManager 直接构造管理器（绕过单例），接指定的缓存后端
func newTestManager(t *testing.T, store cache.CacheStore) *IPFailureManager {
	t.Helper()
	oldEnabled, oldLock := global.GCONFIG_IP_FAILURE_BAN_ENABLED, global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME
	global.GCONFIG_IP_FAILURE_BAN_ENABLED = 1
	global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME = 10
	t.Cleanup(func() {
		global.GCONFIG_IP_FAILURE_BAN_ENABLED, global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME = oldEnabled, oldLock
	})
	return &IPFailureManager{cache: store}
}

func failureLog(ip string, status int) *innerbean.WebLog {
	return &innerbean.WebLog{SRC_IP: ip, STATUS_CODE: status}
}

// 双后端套件：每个用例分别跑在内存后端与 JSON 泛型后端上
func bothBackends() map[string]func() cache.CacheStore {
	return map[string]func() cache.CacheStore{
		"内存后端":     func() cache.CacheStore { return cache.InitWafCache() },
		"JSON泛型后端": func() cache.CacheStore { return cachetest.NewJSONRoundTrip() },
	}
}

// 失败记录必须跨写入累计：连续 5 次失败，窗口内计数应为 5。
// JSON 后端若读回时丢类型，计数会永远停在 1。
func TestRecordFailureAccumulates(t *testing.T) {
	for name, newStore := range bothBackends() {
		t.Run(name, func(t *testing.T) {
			m := newTestManager(t, newStore())
			ip := "192.0.2.1"
			for i := 0; i < 5; i++ {
				m.RecordFailure(failureLog(ip, 403))
			}
			if got := m.GetFailureCount(ip, 10); got != 5 {
				t.Fatalf("5次失败应累计为5，实际 %d", got)
			}
		})
	}
}

// 规则命中盖阈值戳 → 记录带阈值信息，满足封禁列表的收录判据
// （与 api.GetBanIpListApi 一致：TriggerMinutes/TriggerCount 非 0 才显示）。
func TestFailureThresholdStampsRecord(t *testing.T) {
	for name, newStore := range bothBackends() {
		t.Run(name, func(t *testing.T) {
			m := newTestManager(t, newStore())
			ip := "192.0.2.2"
			for i := 0; i < 10; i++ {
				m.RecordFailure(failureLog(ip, 403))
			}
			m.RecordFailureThreshold(ip, 5, 10)

			record := m.GetFailureInfo(ip)
			if record == nil {
				t.Fatal("应有失败记录")
			}
			if record.TriggerMinutes != 5 || record.TriggerCount != 10 {
				t.Fatalf("阈值戳应为 5分钟/10次，实际 %d分钟/%d次", record.TriggerMinutes, record.TriggerCount)
			}
			// 封禁列表收录判据（对齐 api 层的过滤条件）
			if record.TriggerMinutes == 0 || record.TriggerCount == 0 {
				t.Fatal("带阈值戳的记录应出现在封禁列表")
			}

			m.ClearIPFailure(ip)
			if m.GetFailureInfo(ip) != nil {
				t.Fatal("清除后不应再有记录")
			}
		})
	}
}

// 先盖阈值戳（规则先命中、失败记录后到）再累计失败，两种顺序下阈值戳都不能丢
func TestThresholdStampSurvivesLaterFailures(t *testing.T) {
	for name, newStore := range bothBackends() {
		t.Run(name, func(t *testing.T) {
			m := newTestManager(t, newStore())
			ip := "192.0.2.3"
			m.RecordFailureThreshold(ip, 5, 10)
			m.RecordFailure(failureLog(ip, 404))

			record := m.GetFailureInfo(ip)
			if record == nil {
				t.Fatal("应有失败记录")
			}
			if record.TriggerCount != 10 {
				t.Fatalf("后续失败记录不应抹掉阈值戳，实际阈值 %d", record.TriggerCount)
			}
			if record.Count != 1 {
				t.Fatalf("应有1次失败事件，实际 %d", record.Count)
			}
		})
	}
}

// 取出的记录快照不可变：后续写入必须生成新对象，不能原地改缓存里的快照。
// 旧代码在内存后端下原地追加共享切片，先取的引用会被悄悄改掉。
func TestRecordSnapshotImmutable(t *testing.T) {
	for name, newStore := range bothBackends() {
		t.Run(name, func(t *testing.T) {
			m := newTestManager(t, newStore())
			ip := "192.0.2.4"
			m.RecordFailure(failureLog(ip, 403))
			m.RecordFailure(failureLog(ip, 403))

			snap := m.GetFailureInfo(ip)
			if snap == nil || snap.Count != 2 {
				t.Fatalf("快照应有2次失败，实际 %+v", snap)
			}

			// 后续写入不应污染已取出的快照
			m.RecordFailure(failureLog(ip, 403))
			m.RecordFailureThreshold(ip, 5, 10)
			if snap.Count != 2 {
				t.Fatalf("已取出的快照计数被后续写入污染：%d", snap.Count)
			}
			if snap.TriggerCount != 0 {
				t.Fatalf("已取出的快照阈值戳被后续写入污染：%d", snap.TriggerCount)
			}

			// 新读取应看到最新状态
			fresh := m.GetFailureInfo(ip)
			if fresh.Count != 3 || !IsBannedRecord(fresh) {
				t.Fatalf("新读取应看到3次失败且带阈值戳，实际 %+v", fresh)
			}
		})
	}
}
