package cache

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// secondSecurityClient 使用相同 namespace 但独立连接池，排除进程内互斥锁掩盖数据库竞争。
func secondSecurityClient(t *testing.T, p *PostgresCache) *PostgresCache {
	t.Helper()
	other, err := NewPostgresCache(&PostgresCacheConfig{DSN: os.Getenv("SAMWAF_TEST_PG_CACHE_DSN"), Namespace: p.namespace, OpTimeout: 5 * time.Second, PoolSize: 12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	return other
}

// TestPostgresSecurityBatchAndFailure 验证合并查询的 TTL/隔离/取消语义，以及故障不会变为空结果。
func TestPostgresSecurityBatchAndFailure(t *testing.T) {
	p := pgCacheTest(t)
	p.SetWithTTl("ban-a", 1, time.Minute)
	p.SetWithTTl("ban-b", 2, time.Minute)
	hits, err := p.ExistsManyE(context.Background(), []string{"ban-a", "missing", "ban-b"})
	if err != nil || !hits["ban-a"] || !hits["ban-b"] || hits["missing"] {
		t.Fatalf("hits=%v err=%v", hits, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = p.ExistsManyE(ctx, []string{"ban-a"}); !errors.Is(err, ErrCacheBackend) {
		t.Fatalf("cancelled lookup lost error: %v", err)
	}
	if err = p.RemoveE("ban-a"); err != nil {
		t.Fatal(err)
	}
	hits, err = p.ExistsManyE(context.Background(), []string{"ban-a"})
	if err != nil || hits["ban-a"] {
		t.Fatalf("revocation not visible: %v %v", hits, err)
	}
}

// TestPostgresSecurityJSONAtomic 验证两个独立客户端的读改写不会丢更新，失败回调也不会覆盖旧值。
func TestPostgresSecurityJSONAtomic(t *testing.T) {
	p := pgCacheTest(t)
	other := secondSecurityClient(t, p)
	stores := []*PostgresCache{p, other}
	var wg sync.WaitGroup
	errs := make(chan error, 80)
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := stores[i%2].UpdateJSONE("failure-record", time.Minute, func(previous []byte) ([]byte, error) {
				var n int
				if len(previous) > 0 {
					if err := json.Unmarshal(previous, &n); err != nil {
						return nil, err
					}
				}
				return json.Marshal(n + 1)
			})
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	value, err := p.GetInt("failure-record")
	if err != nil || value != 80 {
		t.Fatalf("lost concurrent updates: %d %v", value, err)
	}
	if err = p.UpdateJSONE("failure-record", time.Minute, func([]byte) ([]byte, error) { return nil, errors.New("abort mutation") }); err == nil {
		t.Fatal("expected mutation rollback")
	}
	value, err = other.GetInt("failure-record")
	if err != nil || value != 80 {
		t.Fatalf("failed mutation changed committed state: %d %v", value, err)
	}
}

// TestPostgresSharedCounters 验证共享计数、配额、两种旧 CC 算法及规则清理边界。
func TestPostgresSharedCounters(t *testing.T) {
	p := pgCacheTest(t)
	other := secondSecurityClient(t, p)
	t.Cleanup(func() { _ = p.DropSecurityCounters("") })
	stores := []*PostgresCache{p, other}
	var wg sync.WaitGroup
	errs := make(chan error, 80)
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, _, _, err := stores[i%2].SecurityCount("cc|shared|60", "ip", "buckets", 60, 0, 1000, 10)
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	count, _, _, _, err := other.SecurityCount("cc|shared|60", "ip", "buckets", 60, 0, 1000, 10)
	if err != nil || count != 81 {
		t.Fatalf("shared count=%d err=%v", count, err)
	}
	for _, dim := range []string{"a", "b"} {
		_, _, _, _, err = p.SecurityCount("cc|quota|60", dim, "buckets", 60, 0, 1000, 2)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, _, degraded, rejected, err := p.SecurityCount("cc|quota|60", "c", "buckets", 60, 0, 1000, 2)
	if err != nil || !degraded || rejected {
		t.Fatalf("scope quota: degraded=%v rejected=%v err=%v", degraded, rejected, err)
	}
	for _, mode := range []string{"rate", "window"} {
		scope := "legacy|" + mode
		for i := 0; i < 4; i++ {
			_, allowed, _, _, err := stores[i%2].SecurityCount(scope, "ip", mode, 2, 3, 1000, 10)
			if err != nil || allowed != (i < 3) {
				t.Fatalf("%s request %d: allowed=%v err=%v", mode, i, allowed, err)
			}
		}
	}
	if err = p.DropSecurityCounters("cc|"); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err = p.db.QueryRow("SELECT count(*) FROM samwaf_security.counters WHERE namespace=$1", p.namespace).Scan(&remaining); err != nil || remaining != 2 {
		t.Fatalf("rule cleanup crossed legacy scope: %d %v", remaining, err)
	}
}
