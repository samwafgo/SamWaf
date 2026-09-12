package cache

import (
	"errors"
	"testing"
	"time"
)

// 缓存读取失败必须能区分"键不存在"与"后端不可用"。
// 内存后端不会有后端故障，所有未命中一律是 ErrCacheMiss；
// 凡是拿缓存做凭证判定的链路都按 errors.Is 分流，这里把语义钉死。

type demoVal struct {
	Name string `json:"name"`
}

func TestMemoryCacheMissIsSentinel(t *testing.T) {
	c := InitWafCache()

	var out demoVal
	if err := c.GetAs("NOT_EXIST", &out); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("GetAs 未命中应返回 ErrCacheMiss，实际 %v", err)
	}
	if err := c.GetAsEx("NOT_EXIST", &out, time.Minute); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("GetAsEx 未命中应返回 ErrCacheMiss，实际 %v", err)
	}
	if err := c.Touch("NOT_EXIST", time.Minute); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("Touch 未命中应返回 ErrCacheMiss，实际 %v", err)
	}
	if _, err := c.GetString("NOT_EXIST"); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("GetString 未命中应返回 ErrCacheMiss，实际 %v", err)
	}
	if _, err := c.GetInt("NOT_EXIST"); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("GetInt 未命中应返回 ErrCacheMiss，实际 %v", err)
	}
	if _, err := c.GetBytes("NOT_EXIST"); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("GetBytes 未命中应返回 ErrCacheMiss，实际 %v", err)
	}
	if _, err := c.GetExpireTime("NOT_EXIST"); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("GetExpireTime 未命中应返回 ErrCacheMiss，实际 %v", err)
	}

	// 内存后端永远不会报后端故障
	if err := c.GetAs("NOT_EXIST", &out); errors.Is(err, ErrCacheBackend) {
		t.Fatal("内存后端不应出现 ErrCacheBackend")
	}
	ok, err := c.ExistsE("NOT_EXIST")
	if ok || err != nil {
		t.Fatalf("ExistsE 未命中应返回 (false, nil)，实际 (%v, %v)", ok, err)
	}
}

func TestMemoryGetAsExRenews(t *testing.T) {
	c := InitWafCache()
	c.SetWithTTl("K", demoVal{Name: "n1"}, 2*time.Second)

	time.Sleep(1200 * time.Millisecond)

	// 读取的同时把有效期重置为 2 秒，原到期时刻（约 800ms 后）作废
	var out demoVal
	if err := c.GetAsEx("K", &out, 2*time.Second); err != nil {
		t.Fatalf("GetAsEx 应命中，实际 %v", err)
	}
	if out.Name != "n1" {
		t.Fatalf("取到的值不对：%v", out.Name)
	}

	time.Sleep(1200 * time.Millisecond)
	if err := c.GetAsEx("K", &out, 2*time.Second); err != nil {
		t.Fatalf("续期后本应仍然有效，实际 %v", err)
	}
}

func TestMemoryGetAsExWithoutTTlDoesNotRenew(t *testing.T) {
	c := InitWafCache()
	c.SetWithTTl("K", demoVal{Name: "n1"}, time.Second)

	var out demoVal
	// ttl<=0 表示只读不续期
	if err := c.GetAsEx("K", &out, 0); err != nil {
		t.Fatalf("应命中，实际 %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := c.GetAsEx("K", &out, 0); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("未续期则应已过期，实际 %v", err)
	}
}

func TestMemoryTouchKeepsValue(t *testing.T) {
	c := InitWafCache()
	c.SetWithTTl("K", demoVal{Name: "n1"}, time.Second)

	if err := c.Touch("K", 3*time.Second); err != nil {
		t.Fatalf("Touch 应成功，实际 %v", err)
	}
	time.Sleep(1200 * time.Millisecond)

	var out demoVal
	if err := c.GetAs("K", &out); err != nil {
		t.Fatalf("Touch 后应仍然有效，实际 %v", err)
	}
	if out.Name != "n1" {
		t.Fatalf("Touch 不应改变值，实际 %v", out.Name)
	}
}

// 键名里可能直接跟着凭证本体，日志只能出现前缀加 8 个字符
func TestMaskCacheKey(t *testing.T) {
	cases := []struct{ in, want string }{
		{"CACHE_TOKEN0d42ce0c1f2a3b4c5d6e7f8091a2b3c4", "CACHE_TOKEN0d42ce0c..."},
		{"CACHE_TOKEN_BINDFAIL_0d42ce0c1f2a3b4c", "CACHE_TOKEN_BINDFAIL_0d42ce0c..."},
		{"CACHE_TOKEN", "CACHE_TOKEN"},
		{"CACHE_X_abc", "CACHE_X_abc"},
	}
	for _, tc := range cases {
		if got := maskCacheKey(tc.in); got != tc.want {
			t.Fatalf("maskCacheKey(%q)=%q，期望 %q", tc.in, got, tc.want)
		}
	}
}
