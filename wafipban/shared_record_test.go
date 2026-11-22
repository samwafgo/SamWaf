package wafipban

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"SamWaf/cache"
	"SamWaf/global"
	"SamWaf/innerbean"
)

// TestPostgresFailureRecordsAcrossManagers 验证独立管理器/连接池之间事件和阈值戳不会互相覆盖。
func TestPostgresFailureRecordsAcrossManagers(t *testing.T) {
	dsn := os.Getenv("SAMWAF_TEST_PG_CACHE_DSN")
	if dsn == "" {
		t.Skip("requires an isolated PostgreSQL test database")
	}
	namespace := fmt.Sprintf("failure-record-%x", time.Now().UnixNano())
	stores := []*cache.PostgresCache{}
	for i := 0; i < 2; i++ {
		store, err := cache.NewPostgresCache(&cache.PostgresCacheConfig{DSN: dsn, Namespace: namespace, PoolSize: 12, OpTimeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		stores = append(stores, store)
	}
	t.Cleanup(func() {
		keys, err := cache.KeysE(stores[0], "")
		if err == nil {
			for key := range keys {
				_ = stores[0].RemoveE(key)
			}
		}
		for _, store := range stores {
			_ = store.Close()
		}
	})
	oldEnabled, oldLock := global.GCONFIG_IP_FAILURE_BAN_ENABLED, global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME
	global.GCONFIG_IP_FAILURE_BAN_ENABLED = 1
	global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME = 10
	t.Cleanup(func() {
		global.GCONFIG_IP_FAILURE_BAN_ENABLED = oldEnabled
		global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME = oldLock
	})
	managers := []*IPFailureManager{{cache: stores[0]}, {cache: stores[1]}}
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := managers[i%2].RecordFailure(&innerbean.WebLog{SRC_IP: "198.51.100.7", URL: "/failed", RISK_LEVEL: 1}); err != nil {
				errs <- err
			}
		}(i)
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := managers[i%2].RecordFailureThreshold("198.51.100.7", 5, 10); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	record := managers[0].GetFailureInfo("198.51.100.7")
	if record == nil || record.Count != 80 || len(record.Events) != 80 || record.TriggerMinutes != 5 || record.TriggerCount != 10 {
		t.Fatalf("events or threshold lost: %+v", record)
	}
	logins := []*HostLoginFailureManager{{cache: stores[0]}, {cache: stores[1]}}
	errorsLogin := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := logins[i%2].RecordE("ssh", "198.51.100.7", 10, 30); err != nil {
				errorsLogin <- err
			}
		}(i)
	}
	wg.Wait()
	close(errorsLogin)
	for err := range errorsLogin {
		t.Fatal(err)
	}
	if got := logins[0].GetCount("ssh", "198.51.100.7", 10); got != 40 {
		t.Fatalf("lost shared SSH failures: %d", got)
	}
	if got := managers[1].GetFailureCount("198.51.100.7", 5); got != 80 {
		t.Fatalf("SSH failures contaminated HTTP counter: %d", got)
	}
}
