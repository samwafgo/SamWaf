package webplugin

import (
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// 回归：平均速率模式下 window 字段一直是 0，CleanupOldRecords 拿它去算过期时间，
// 结果每次清理都把所有令牌桶整表删掉重建 —— 定时任务默认 5 分钟跑一次，
// 等于按固定周期给正在被限流的客户端重置一次满桶。
func TestCleanupOldRecords_RateModeKeepsActiveBucket(t *testing.T) {
	// 每秒 10 个、突发 10 个：等价窗口约 2 秒
	limiter := NewIPRateLimiter(rate.Limit(10), 10)
	ip := "203.0.113.10"

	for n := 0; n < 10; n++ {
		limiter.Allow(ip)
	}
	if limiter.Allow(ip) {
		t.Fatal("令牌耗尽后仍然放行，用例前提不成立")
	}

	limiter.CleanupOldRecords()

	if limiter.Allow(ip) {
		t.Error("清理后立刻又放行了：活跃客户端的令牌桶被清理任务删掉重建，限流形同虚设")
	}
	if limiter.TrackedIPCount() == 0 {
		t.Error("活跃客户端不应在清理中被回收")
	}
}

// 另一面：空闲足够久的客户端必须能被回收，否则 map 只增不减。
// 空闲超过「补满一桶所需时间」后，删与不删对限流效果等价，回收是安全的。
func TestCleanupOldRecords_RateModeReclaimsIdle(t *testing.T) {
	limiter := NewIPRateLimiter(rate.Limit(10), 10)
	ip := "203.0.113.11"
	limiter.Allow(ip)

	if limiter.TrackedIPCount() != 1 {
		t.Fatalf("应跟踪 1 个客户端，实际 %d", limiter.TrackedIPCount())
	}

	// 等价窗口 = 10/10 + 1 = 2 秒
	time.Sleep(time.Duration(limiter.WindowSeconds()+1) * time.Second)
	limiter.CleanupOldRecords()

	if limiter.TrackedIPCount() != 0 {
		t.Errorf("空闲客户端应被回收，实际仍跟踪 %d 个", limiter.TrackedIPCount())
	}
}
