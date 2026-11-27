package wafenginecore

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/wafenginmodel"
	pg "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestIPBlockPostgresWorkerSync 用两个真实引擎验证跨 Worker 的迁移、删除与读取故障保留。
func TestIPBlockPostgresWorkerSync(t *testing.T) {
	dsn := os.Getenv("SAMWAF_TEST_PG_CACHE_DSN")
	if dsn == "" {
		t.Skip("requires an isolated PostgreSQL test database")
	}
	base, err := gorm.Open(pg.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("samwaf_ip_sync_%x", time.Now().UnixNano())
	if err = base.Exec(`CREATE SCHEMA "` + schema + `"`).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = base.Exec(`DROP SCHEMA "` + schema + `" CASCADE`).Error
		raw, _ := base.DB()
		_ = raw.Close()
	})
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema+",public")
	parsed.RawQuery = query.Encode()
	db, err := gorm.Open(pg.Open(parsed.String()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := db.DB()
	t.Cleanup(func() { raw.Close() })
	if err = db.AutoMigrate(&model.IPBlockList{}); err != nil {
		t.Fatal(err)
	}
	row := model.IPBlockList{BaseOrm: baseorm.BaseOrm{Id: "sync-rule"}, HostCode: "sync-a", Ip: "198.51.100.7", IsEnable: 1}
	if err = db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	workers := []*WafEngine{{}, {}}
	for _, worker := range workers {
		worker.InitRouting()
		worker.withWriteTable(func(table *routingTable) {
			for _, code := range []string{"sync-a", "sync-b"} {
				host := &wafenginmodel.HostSafe{Host: model.Hosts{Code: code, GUARD_STATUS: 1, IPMode: "nic"}}
				table.HostTarget[code] = host
				table.HostCode[code] = code
			}
		})
		if err = worker.StartIPBlockSync(db); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(worker.StopIPBlockSync)
	}
	blocked := func(worker *WafEngine, code string) bool {
		host, _ := worker.GetHostByCode(code)
		result := worker.CheckDenyIP(nil, &innerbean.WebLog{NetSrcIp: row.Ip, SRC_IP: row.Ip}, nil, host, nil)
		return result.IsBlock
	}
	for _, worker := range workers {
		if !blocked(worker, "sync-a") || blocked(worker, "sync-b") {
			t.Fatal("initial policy was not loaded")
		}
	}
	oldSnapshot, _ := workers[0].GetHostByCode("sync-a")
	if err = db.Model(&row).Update("host_code", "sync-b").Error; err != nil {
		t.Fatal(err)
	}
	wait := func(predicate func() bool) {
		t.Helper()
		end := time.Now().Add(4 * time.Second)
		for time.Now().Before(end) {
			if predicate() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("workers did not converge to committed IP policy")
	}
	wait(func() bool {
		for _, worker := range workers {
			if blocked(worker, "sync-a") || !blocked(worker, "sync-b") {
				return false
			}
		}
		return true
	})
	if !oldSnapshot.IPBlockIndex.ContainsStr(row.Ip) {
		t.Fatal("old immutable snapshot was modified in place")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = workers[0].ReloadIPBlocks(cancelled, db); err == nil {
		t.Fatal("cancelled database read reported success")
	}
	if !blocked(workers[0], "sync-b") {
		t.Fatal("failed reload erased the effective blacklist")
	}
	if err = db.Delete(&row).Error; err != nil {
		t.Fatal(err)
	}
	wait(func() bool {
		for _, worker := range workers {
			if blocked(worker, "sync-b") {
				return false
			}
		}
		return true
	})
}
