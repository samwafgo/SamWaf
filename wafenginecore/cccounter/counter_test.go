package cccounter

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// newTestCounter 返回一个时间可控的计数器。
func newTestCounter(t *testing.T, maxKeys int64, quota int) (*Counter, func(sec int64)) {
	t.Helper()
	c := New(maxKeys, quota)
	base := time.Unix(1_700_000_000, 0)
	cur := base
	c.nowFn = func() time.Time { return cur }
	return c, func(sec int64) { cur = cur.Add(time.Duration(sec) * time.Second) }
}

func TestIncr_AccumulatesWithinWindow(t *testing.T) {
	c, _ := newTestCounter(t, 0, 0)
	for i := 1; i <= 5; i++ {
		got := c.Incr("rule-1", "1.2.3.4", 60)
		if got.Count != int64(i) {
			t.Fatalf("第%d次计数应为 %d，实际 %d", i, i, got.Count)
		}
		if got.Degraded || got.Rejected {
			t.Fatalf("正常计数不应降级或被拒绝: %+v", got)
		}
	}
}

// 滑动窗口的核心：时间推进后早先的计数要逐步滑出，而不是到点整体清零。
func TestIncr_OldBucketsSlideOut(t *testing.T) {
	c, advance := newTestCounter(t, 0, 0)
	const window = 60 // 桶宽 6 秒

	c.Incr("rule-1", "ip", window) // 落在第 0 个桶
	advance(6)
	c.Incr("rule-1", "ip", window) // 第 1 个桶
	if got := c.Incr("rule-1", "ip", window); got.Count != 3 {
		t.Fatalf("窗口内应累计 3 次，实际 %d", got.Count)
	}

	// 推进整整一个窗口，先前的桶应当全部滑出
	advance(window)
	if got := c.Incr("rule-1", "ip", window); got.Count != 1 {
		t.Errorf("跨过整个窗口后应只剩本次计数，实际 %d（旧桶没有被清零？）", got.Count)
	}
}

// 不同规则、不同维度取值之间必须互不干扰；
// 维度取值来自外部输入，即使带上分隔符也不能串到别的规则的计数上。
func TestIncr_KeysAreIsolated(t *testing.T) {
	c, _ := newTestCounter(t, 0, 0)

	c.Incr("rule-A", "1.1.1.1", 60)
	c.Incr("rule-A", "1.1.1.1", 60)
	c.Incr("rule-A", "2.2.2.2", 60)

	if got := c.Incr("rule-B", "1.1.1.1", 60); got.Count != 1 {
		t.Errorf("不同规则应各自计数，rule-B 实际 %d", got.Count)
	}
	if got := c.Incr("rule-A", "2.2.2.2", 60); got.Count != 2 {
		t.Errorf("不同维度取值应各自计数，实际 %d", got.Count)
	}

	// 构造一个试图伪装成 "rule-A:xxx" 的取值
	evil := "rule-A:deadbeef"
	if got := c.Incr("rule-B", evil, 60); got.Count != 1 {
		t.Errorf("带分隔符的取值不应串到别的计数上，实际 %d", got.Count)
	}
}

// 维度取值超长时先截断再哈希，不能因为超长就拒绝计数或撑大内存。
func TestIncr_LongDimValueTruncated(t *testing.T) {
	c, _ := newTestCounter(t, 0, 0)
	long := make([]byte, maxDimValueLen*4)
	for i := range long {
		long[i] = 'a'
	}
	// 前 maxDimValueLen 字节相同、之后不同的两个取值会落到同一个键（截断的预期代价）
	a := string(long)
	b := string(long) + "different-tail"
	c.Incr("rule-1", a, 60)
	if got := c.Incr("rule-1", b, 60); got.Count != 2 {
		t.Errorf("超长取值应被截断到同一计数键，实际 %d", got.Count)
	}
}

// 拿可伪造字段当统计维度时，攻击者每个请求换一个取值会让计数键无限增长。
// 超过单规则配额后必须降级，而不是继续吃内存。
func TestIncr_RuleQuotaTriggersDegrade(t *testing.T) {
	const quota = 10
	c, _ := newTestCounter(t, 0, quota)

	for i := 0; i < quota; i++ {
		got := c.Incr("rule-1", fmt.Sprintf("forged-%d", i), 60)
		if got.Degraded {
			t.Fatalf("配额内第%d个取值不应降级", i)
		}
	}
	got := c.Incr("rule-1", "forged-overflow", 60)
	if !got.Degraded {
		t.Fatal("超过单规则配额后应降级，提示调用方改用 IP 维度")
	}
	if c.ActiveKeys() != quota {
		t.Errorf("降级后不应再新建计数键，实际 %d 个", c.ActiveKeys())
	}
	// 已存在的键仍然正常计数，降级只影响新键
	if again := c.Incr("rule-1", "forged-0", 60); again.Count != 2 || again.Degraded {
		t.Errorf("已有计数键应继续正常累加: %+v", again)
	}
	if c.Stats()["degraded_count"] == 0 {
		t.Error("降级次数应被计量，供运行诊断观察")
	}
}

// 总量到顶时只能放弃计数，这是 WAF 自身的存活线。
func TestIncr_GlobalCapRejects(t *testing.T) {
	c, _ := newTestCounter(t, 5, 1000)
	for i := 0; i < 5; i++ {
		c.Incr("rule-1", fmt.Sprintf("ip-%d", i), 60)
	}
	got := c.Incr("rule-1", "ip-overflow", 60)
	if !got.Rejected {
		t.Fatal("计数键总量到达上限后应拒绝新建")
	}
	if got.Degraded {
		t.Error("总量到顶属于拒绝而非降级，两者含义不同（降级可重试、拒绝不可）")
	}
}

func TestCleanup_ReclaimsIdleKeysAndQuota(t *testing.T) {
	const quota = 2
	c, advance := newTestCounter(t, 0, quota)
	c.Incr("rule-1", "a", 60)
	c.Incr("rule-1", "b", 60)
	if got := c.Incr("rule-1", "c", 60); !got.Degraded {
		t.Fatal("用例前提：配额应已用尽")
	}

	advance(600)
	if removed := c.Cleanup(300); removed != 2 {
		t.Fatalf("应回收 2 个空闲计数键，实际 %d", removed)
	}
	if c.ActiveKeys() != 0 {
		t.Errorf("回收后计数键应清零，实际 %d", c.ActiveKeys())
	}
	// 配额随之释放，新取值可以重新计数
	if got := c.Incr("rule-1", "d", 60); got.Degraded {
		t.Error("回收后配额应释放，不应继续降级")
	}
}

func TestCleanup_KeepsActiveKeys(t *testing.T) {
	c, advance := newTestCounter(t, 0, 0)
	c.Incr("rule-1", "active", 60)
	advance(10)
	c.Incr("rule-1", "active", 60)

	if removed := c.Cleanup(300); removed != 0 {
		t.Errorf("活跃计数键不应被回收，实际回收 %d 个", removed)
	}
	if got := c.Incr("rule-1", "active", 60); got.Count != 3 {
		t.Errorf("活跃键的计数应保留，实际 %d", got.Count)
	}
}

func TestDropRule(t *testing.T) {
	c, _ := newTestCounter(t, 0, 0)
	c.Incr("rule-1", "a", 60)
	c.Incr("rule-1", "b", 60)
	c.Incr("rule-2", "a", 60)

	c.DropRule("rule-1")
	if c.ActiveKeys() != 1 {
		t.Errorf("删除规则应释放它的全部计数键，实际剩 %d", c.ActiveKeys())
	}
	if got := c.Incr("rule-2", "a", 60); got.Count != 2 {
		t.Errorf("其他规则的计数不应受影响，实际 %d", got.Count)
	}
}

// 计数器在攻击场景下会被高并发访问，必须能在 -race 下跑干净。
func TestIncr_Concurrent(t *testing.T) {
	c := New(0, 0)
	const goroutines, perG = 32, 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				c.Incr("rule-1", "same-client", 600)
				c.Incr("rule-1", fmt.Sprintf("client-%d", g), 600)
			}
		}(g)
	}
	wg.Wait()

	// 同一个客户端的计数必须一次不丢
	got := c.Incr("rule-1", "same-client", 600)
	if want := int64(goroutines*perG + 1); got.Count != want {
		t.Errorf("并发累加应为 %d，实际 %d", want, got.Count)
	}
	if c.ActiveKeys() != int64(goroutines+1) {
		t.Errorf("应有 %d 个计数键，实际 %d", goroutines+1, c.ActiveKeys())
	}
}

func TestStats(t *testing.T) {
	c, _ := newTestCounter(t, 100, 10)
	c.Incr("rule-1", "a", 60)
	s := c.Stats()
	if s["active_keys"] != 1 || s["tracked_rules"] != 1 || s["max_keys"] != 100 {
		t.Errorf("计量值不正确: %+v", s)
	}
}
