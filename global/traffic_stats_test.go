package global

import (
	"sync"
	"testing"
	"time"
)

// 每个用例开头先清空，避免包内用例互相污染
func resetTraffic() { DrainTraffic() }

// 分桶必须由「请求发生时刻」决定：这是本次改造最容易写错、错了又最难查的地方
// （落库时刻分桶会把 23:59:50 的流量记到第二天，总量对、分布错）。
func TestTrafficBucketOf(t *testing.T) {
	cases := []struct {
		name     string
		ts       time.Time
		wantDay  int
		wantHour time.Time
	}{
		{"整点前一秒", time.Date(2026, 8, 18, 23, 59, 59, 0, time.Local), 20260818, time.Date(2026, 8, 18, 23, 0, 0, 0, time.Local)},
		{"跨天后一秒", time.Date(2026, 8, 19, 0, 0, 1, 0, time.Local), 20260819, time.Date(2026, 8, 19, 0, 0, 0, 0, time.Local)},
		{"月初", time.Date(2026, 9, 1, 12, 34, 56, 0, time.Local), 20260901, time.Date(2026, 9, 1, 12, 0, 0, 0, time.Local)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			day, hour := TrafficBucketOf(c.ts)
			if day != c.wantDay {
				t.Fatalf("day = %d, 期望 %d", day, c.wantDay)
			}
			if hour != c.wantHour.Unix() {
				t.Fatalf("hourTime = %d(%s), 期望 %d(%s)",
					hour, time.Unix(hour, 0), c.wantHour.Unix(), c.wantHour)
			}
		})
	}
}

// 同一秒的两次请求必须落同一个桶；跨天/跨整点必须落不同桶
func TestAddTraffic_BucketSeparation(t *testing.T) {
	resetTraffic()
	d1, h1 := TrafficBucketOf(time.Date(2026, 8, 18, 23, 59, 50, 0, time.Local))
	d2, h2 := TrafficBucketOf(time.Date(2026, 8, 19, 0, 0, 10, 0, time.Local))

	AddTraffic("h1", "a.com", d1, h1, 100, 200)
	AddTraffic("h1", "a.com", d1, h1, 1, 2) // 同桶累加
	AddTraffic("h1", "a.com", d2, h2, 10, 20)

	got := DrainTraffic()
	if len(got) != 2 {
		t.Fatalf("期望 2 个桶（跨天必须分开），实际 %d 个: %+v", len(got), got)
	}
	for _, s := range got {
		switch s.Day {
		case d1:
			if s.In != 101 || s.Out != 202 {
				t.Fatalf("旧一天的桶 in/out = %d/%d，期望 101/202", s.In, s.Out)
			}
		case d2:
			if s.In != 10 || s.Out != 20 {
				t.Fatalf("新一天的桶 in/out = %d/%d，期望 10/20", s.In, s.Out)
			}
		default:
			t.Fatalf("出现意外的 day=%d", s.Day)
		}
	}
}

// 不同站点各记各的账，不能串
func TestAddTraffic_PerHost(t *testing.T) {
	resetTraffic()
	day, hour := TrafficBucketOf(time.Now())
	AddTraffic("hostA", "a.com", day, hour, 5, 7)
	AddTraffic("hostB", "b.com", day, hour, 50, 70)

	got := DrainTraffic()
	if len(got) != 2 {
		t.Fatalf("期望 2 个站点桶，实际 %d", len(got))
	}
	m := map[string][2]int64{}
	for _, s := range got {
		m[s.HostCode] = [2]int64{s.In, s.Out}
		if s.HostCode == "hostA" && s.Host != "a.com" {
			t.Fatalf("host 字段串了: %s", s.Host)
		}
	}
	if m["hostA"] != [2]int64{5, 7} || m["hostB"] != [2]int64{50, 70} {
		t.Fatalf("站点账目不对: %+v", m)
	}
}

// Drain 必须是「取走」：取完就清零，再取为空
func TestDrainTraffic_ClearsAfterDrain(t *testing.T) {
	resetTraffic()
	day, hour := TrafficBucketOf(time.Now())
	AddTraffic("h", "a.com", day, hour, 1, 1)
	if n := PendingTrafficBuckets(); n != 1 {
		t.Fatalf("待落库桶数 = %d，期望 1", n)
	}
	if got := DrainTraffic(); len(got) != 1 {
		t.Fatalf("首次 Drain 应拿到 1 个桶，实际 %d", len(got))
	}
	if n := PendingTrafficBuckets(); n != 0 {
		t.Fatalf("Drain 后应清零，实际剩 %d 个桶", n)
	}
	if got := DrainTraffic(); len(got) != 0 {
		t.Fatalf("二次 Drain 应为空，实际 %d 个桶（会造成重复计数）", len(got))
	}
}

// 无效输入直接丢弃：没有 host_code 的流量无处归属，负数/全零不该建桶
func TestAddTraffic_IgnoresInvalid(t *testing.T) {
	resetTraffic()
	day, hour := TrafficBucketOf(time.Now())
	AddTraffic("", "a.com", day, hour, 100, 100) // 无 host_code
	AddTraffic("h", "a.com", day, hour, 0, 0)    // 全零
	AddTraffic("h", "a.com", day, hour, -5, -5)  // 负数
	if n := PendingTrafficBuckets(); n != 0 {
		t.Fatalf("无效输入不应建桶，实际 %d 个", n)
	}

	// 一正一负：负的那侧按 0 计，不能把总量拉低
	AddTraffic("h", "a.com", day, hour, -5, 100)
	got := DrainTraffic()
	if len(got) != 1 || got[0].In != 0 || got[0].Out != 100 {
		t.Fatalf("期望 in=0 out=100，实际 %+v", got)
	}
}

// 落库失败要能原样退回，等下轮重试
func TestRestoreTraffic(t *testing.T) {
	resetTraffic()
	day, hour := TrafficBucketOf(time.Now())
	AddTraffic("h", "a.com", day, hour, 11, 22)
	drained := DrainTraffic()

	RestoreTraffic(drained)
	again := DrainTraffic()
	if len(again) != 1 || again[0].In != 11 || again[0].Out != 22 {
		t.Fatalf("退回后应能重新取到同样的账，实际 %+v", again)
	}
}

// 并发累加不能丢字节（热路径是多协程同时写）
func TestAddTraffic_Concurrent(t *testing.T) {
	resetTraffic()
	day, hour := TrafficBucketOf(time.Now())
	const goroutines = 32
	const perG = 500

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			// 一半打同一个站点（最坏争用），一半分散到不同站点
			hostCode := "shared"
			if g%2 == 1 {
				hostCode = "host" + string(rune('A'+g))
			}
			for i := 0; i < perG; i++ {
				AddTraffic(hostCode, "x.com", day, hour, 1, 2)
			}
		}(g)
	}
	wg.Wait()

	var totalIn, totalOut int64
	for _, s := range DrainTraffic() {
		totalIn += s.In
		totalOut += s.Out
	}
	wantIn := int64(goroutines * perG)
	if totalIn != wantIn || totalOut != wantIn*2 {
		t.Fatalf("并发累加丢字节：in=%d(期望 %d) out=%d(期望 %d)", totalIn, wantIn, totalOut, wantIn*2)
	}
}

// 并发 Add 与 Drain 交错时也不能丢：Drain 换走 map 的瞬间必须与写入互斥
func TestAddTraffic_ConcurrentWithDrain(t *testing.T) {
	resetTraffic()
	day, hour := TrafficBucketOf(time.Now())
	const writers = 8
	const perW = 2000

	var collected int64
	var mu sync.Mutex
	stop := make(chan struct{})
	var drainWg sync.WaitGroup
	drainWg.Add(1)
	go func() {
		defer drainWg.Done()
		for {
			select {
			case <-stop:
				for _, s := range DrainTraffic() { // 收尾再取一次
					mu.Lock()
					collected += s.In
					mu.Unlock()
				}
				return
			default:
				for _, s := range DrainTraffic() {
					mu.Lock()
					collected += s.In
					mu.Unlock()
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perW; i++ {
				AddTraffic("h", "a.com", day, hour, 1, 0)
			}
		}()
	}
	wg.Wait()
	close(stop)
	drainWg.Wait()

	if want := int64(writers * perW); collected != want {
		t.Fatalf("Add 与 Drain 交错丢字节：收到 %d，期望 %d", collected, want)
	}
}

func BenchmarkAddTraffic(b *testing.B) {
	day, hour := TrafficBucketOf(time.Now())
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			AddTraffic("bench", "a.com", day, hour, 1024, 4096)
		}
	})
	DrainTraffic()
}
