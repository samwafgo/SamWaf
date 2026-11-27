package cache

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pgCacheTest 连接环境变量明确指定的测试库，用独立 namespace 隔离用例并在结束时清理。
func pgCacheTest(t *testing.T) *PostgresCache {
	t.Helper()
	dsn := os.Getenv("SAMWAF_TEST_PG_CACHE_DSN")
	if dsn == "" {
		t.Skip("set SAMWAF_TEST_PG_CACHE_DSN to an isolated PostgreSQL test database")
	}
	p, err := NewPostgresCache(&PostgresCacheConfig{DSN: dsn, Namespace: fmt.Sprintf("samwaf-test-%x", time.Now().UnixNano()), CleanupInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = p.db.Exec("DELETE FROM samwaf_kv.entries WHERE namespace=$1", p.namespace); p.Close() })
	return p
}

// TestPostgresCacheRoundTrip 校验真实 JSONB 后端的类型还原、结构体泛型语义和未命中错误分类。
func TestPostgresCacheRoundTrip(t *testing.T) {
	p := pgCacheTest(t)
	var version int
	if err := p.db.QueryRow("SELECT samwaf_kv.version()").Scan(&version); err != nil || version != 1 {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	for _, tc := range []struct {
		key   string
		value interface{}
	}{
		{"string", "hello"}, {"int", 42}, {"bytes", []byte{0, 1, 255}}, {"struct", demoVal{Name: "test"}},
	} {
		p.SetWithTTl(tc.key, tc.value, time.Minute)
	}
	if value, err := p.GetString("string"); value != "hello" || err != nil {
		t.Fatalf("string=%q err=%v", value, err)
	}
	if value, err := p.GetInt("int"); value != 42 || err != nil {
		t.Fatalf("int=%d err=%v", value, err)
	}
	if value, err := p.GetBytes("bytes"); !bytes.Equal(value, []byte{0, 1, 255}) || err != nil {
		t.Fatalf("bytes=%v err=%v", value, err)
	}
	var out demoVal
	if err := p.GetAs("struct", &out); err != nil || out.Name != "test" {
		t.Fatalf("struct=%v err=%v", out, err)
	}
	if _, ok := p.Get("struct").(map[string]interface{}); !ok {
		t.Fatal("Get must keep the JSON backend value semantics")
	}
	if err := p.GetAs("missing", &out); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("miss=%v", err)
	}
	if err := p.Touch("missing", time.Minute); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("touch miss=%v", err)
	}
	p.Remove("int")
	if p.IsKeyExist("int") {
		t.Fatal("delete did not remove key")
	}
}

// TestPostgresCacheExpiryRenewalAndCleanup 验证即时过期、原子续期与只删除过期行的物理回收。
func TestPostgresCacheExpiryRenewalAndCleanup(t *testing.T) {
	p := pgCacheTest(t)
	p.SetWithTTl("renew", demoVal{Name: "value"}, time.Second)
	before, err := p.GetExpireTime("renew")
	if err != nil {
		t.Fatal(err)
	}
	var out demoVal
	if err := p.GetAsEx("renew", &out, 10*time.Second); err != nil || out.Name != "value" {
		t.Fatalf("getex=%v err=%v", out, err)
	}
	after, err := p.GetExpireTime("renew")
	if err != nil || after.Sub(before) < 8*time.Second {
		t.Fatalf("renewal before=%v after=%v err=%v", before, after, err)
	}
	if err := p.Touch("renew", 20*time.Second); err != nil {
		t.Fatal(err)
	}
	p.SetWithTTl("expired", 1, time.Minute)
	if _, err := p.db.Exec("UPDATE samwaf_kv.entries SET expires_at=clock_timestamp()-interval '1 second' WHERE namespace=$1 AND cache_key='expired'", p.namespace); err != nil {
		t.Fatal(err)
	}
	if exists, err := p.ExistsE("expired"); exists || err != nil {
		t.Fatalf("expired key exists=%v err=%v", exists, err)
	}
	if _, err := p.GetInt("expired"); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("expired read=%v", err)
	}
	if _, err := p.CleanupExpired(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := p.db.QueryRow("SELECT count(*) FROM samwaf_kv.entries WHERE namespace=$1 AND cache_key='expired'", p.namespace).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expired rows=%d err=%v", count, err)
	}
	if !p.IsKeyExist("renew") {
		t.Fatal("cleanup removed a live credential")
	}
	p.SetWithTTl("renew", 1, 0)
	if p.IsKeyExist("renew") {
		t.Fatal("zero TTL must remove key")
	}
}

// TestPostgresCacheAtomicAddAndCounters 并发争用同键，防止首次占用多赢家、计数丢失和固定窗口被续期。
func TestPostgresCacheAtomicAddAndCounters(t *testing.T) {
	p := pgCacheTest(t)
	var winners atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := p.AddWithTTL("nonce", true, time.Minute)
			if err != nil {
				t.Error(err)
			}
			if ok {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("atomic ADD winners=%d", winners.Load())
	}
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := p.IncrementWithTTL("count", 1, time.Minute, false); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if value, err := p.GetInt("count"); err != nil || value != 240 {
		t.Fatalf("counter=%d err=%v", value, err)
	}
	before, _ := p.GetExpireTime("count")
	if _, err := p.IncrementWithTTL("count", 1, 2*time.Minute, false); err != nil {
		t.Fatal(err)
	}
	after, _ := p.GetExpireTime("count")
	if !before.Equal(after) {
		t.Fatal("fixed-window counter was renewed")
	}
}

// TestPostgresCacheNamespaceAndLiteralPrefix 验证实例之间隔离，并确保 %/_ 不扩大前缀匹配。
func TestPostgresCacheNamespaceAndLiteralPrefix(t *testing.T) {
	p := pgCacheTest(t)
	q := pgCacheTest(t)
	p.SetWithTTl("prefix_%:one", 1, time.Minute)
	p.SetWithTTl("prefix-other", 2, time.Minute)
	if q.IsKeyExist("prefix_%:one") {
		t.Fatal("namespace leaked")
	}
	keys := p.ListAvailableKeysWithPrefix("prefix_%:")
	if len(keys) != 1 {
		t.Fatalf("literal prefix matched %v", keys)
	}
	if _, ok := keys["prefix_%:one"]; !ok {
		t.Fatal("literal key missing")
	}
}

// TestPostgresCacheBackendFailureIsDistinctAndRedacted 模拟关闭连接池，校验故障分类和诊断脱敏。
func TestPostgresCacheBackendFailureIsDistinctAndRedacted(t *testing.T) {
	p := pgCacheTest(t)
	p.note("get", errors.New("synthetic-password synthetic-token"))
	if strings.Contains(p.BackendStats().LastErr, "synthetic") {
		t.Fatal("backend diagnostic leaked values")
	}
	if err := p.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ExistsE("missing"); !errors.Is(err, ErrCacheBackend) {
		t.Fatalf("backend failure=%v", err)
	}
	if p.BackendStats().ErrCount < 2 {
		t.Fatal("backend failures not counted")
	}
}

// TestAtomicMemoryAdd 保证兼容内存适配器也满足防重放所依赖的单赢家契约。
func TestAtomicMemoryAdd(t *testing.T) {
	c := InitWafCache()
	var successes atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := c.AddWithTTL("nonce", true, time.Minute)
			if err != nil {
				t.Error(err)
			}
			if ok {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("atomic add successes=%d", successes.Load())
	}
}
