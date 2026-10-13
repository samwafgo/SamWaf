package wafipban

import (
	"SamWaf/cache"
	"SamWaf/cache/cachetest"
	"testing"
)

// 双后端回归：与 IPFailureManager 同构，计数记录必须跨写入累计、能读回、能清除。
// JSON 类后端(Redis)下若读回丢类型，Record 的返回值会永远停在 1、GetCount 恒 0。
func TestHostLoginRecordLifecycle(t *testing.T) {
	stores := map[string]func() cache.CacheStore{
		"内存后端":     func() cache.CacheStore { return cache.InitWafCache() },
		"JSON泛型后端": func() cache.CacheStore { return cachetest.NewJSONRoundTrip() },
	}
	for name, newStore := range stores {
		t.Run(name, func(t *testing.T) {
			m := &HostLoginFailureManager{cache: newStore()}
			const src = "ssh"

			// 连续 3 次失败，Record 返回的窗口内累计应逐次 +1
			for want := int64(1); want <= 3; want++ {
				if got := m.Record(src, "192.0.2.10", 10, 30); got != want {
					t.Fatalf("第 %d 次失败应累计为 %d，实际 %d", want, want, got)
				}
			}
			if got := m.GetCount(src, "192.0.2.10", 10); got != 3 {
				t.Fatalf("GetCount 应为 3，实际 %d", got)
			}

			// 来源隔离：RDP 的计数不受 SSH 影响
			if got := m.Record("rdp", "192.0.2.10", 10, 30); got != 1 {
				t.Fatalf("另一来源应独立计数，实际 %d", got)
			}

			// 记录可读回
			rec := m.GetRecord(src, "192.0.2.10")
			if rec == nil || rec.Count != 3 {
				t.Fatalf("记录应可读回且为3次，实际 %+v", rec)
			}

			// 清除后归零
			m.Clear(src, "192.0.2.10")
			if m.GetRecord(src, "192.0.2.10") != nil || m.GetCount(src, "192.0.2.10", 10) != 0 {
				t.Fatal("清除后不应再有记录")
			}
			// 另一来源不受影响
			if m.GetCount("rdp", "192.0.2.10", 10) != 1 {
				t.Fatal("清除 SSH 不应影响 RDP 计数")
			}
		})
	}
}
