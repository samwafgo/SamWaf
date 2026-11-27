package wafwebcache

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"SamWaf/model"
)

// TestTierAbandonedReservationRecovered 模拟 Writer 死亡，验证过旧临时文件和预留计数都能被重新扫描回收。
func TestTierAbandonedReservationRecovered(t *testing.T) {
	d := newDiskCache(t.TempDir())
	now := time.Now()
	base := hashFields("orphan")
	m := metadata{Base: base, Key: variantKey(base, nil, nil), Header: make(http.Header), Size: 100, Stored: now.UnixNano(), Expires: now.Add(time.Hour).UnixNano()}
	w, err := d.begin(context.Background(), m, normalize(model.CacheConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	// 模拟进程死亡：句柄已关闭，但未执行 finish；直接回调回滚无法覆盖这种情况。
	w.file.Close()
	old := now.Add(-2 * time.Hour)
	if err := os.Chtimes(w.tmp, old, old); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.lastScan = now.Add(-2 * time.Minute)
	d.mu.Unlock()
	d.maintain(normalize(model.CacheConfig{}))
	d.mu.Lock()
	reserved, pending := d.temps, d.pending
	d.mu.Unlock()
	if reserved != 0 || pending != 0 {
		t.Fatalf("abandoned reservation retained: bytes=%d pending=%d", reserved, pending)
	}
	if _, err := os.Stat(w.tmp); !os.IsNotExist(err) {
		t.Fatal("abandoned temporary file was not reclaimed")
	}
}
