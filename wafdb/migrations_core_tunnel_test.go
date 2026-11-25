package wafdb

import (
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"path/filepath"
	"testing"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
)

func TestTunnelProtectionCoreMigration(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "tunnel-migration.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		t.Cleanup(func() { _ = sqlDB.Close() })
	}
	type legacyTunnel struct {
		baseorm.BaseOrm
		Name string
		Port string
	}
	table := db.Table("tunnels")
	if err := table.AutoMigrate(&legacyTunnel{}); err != nil {
		t.Fatal(err)
	}
	if err := table.Create(&legacyTunnel{BaseOrm: baseorm.BaseOrm{Id: "legacy"}, Name: "Existing", Port: "9112"}).Error; err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := addTunnelProtectionColumns(db); err != nil {
			t.Fatal(err)
		}
	}
	var row model.Tunnel
	if err := db.Where("id = ?", "legacy").Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Name != "Existing" || row.Port != "9112" || row.RegionProtection != "" || row.DDNSProtection != "" {
		t.Fatalf("unexpected legacy row: %+v", row)
	}
	if err := table.Where("id = ?", "legacy").Updates(map[string]any{"region_protection": `{"enabled":true}`, "ddns_protection": `{"bindings":[]}`}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Where("id = ?", "legacy").Take(&row).Error; err != nil || row.RegionProtection == "" || row.DDNSProtection == "" {
		t.Fatalf("new columns did not round trip: %+v, %v", row, err)
	}
}
