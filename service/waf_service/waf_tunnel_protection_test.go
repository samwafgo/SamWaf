package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"context"
	"errors"
	"path/filepath"
	"testing"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupTunnelProtectionTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "tunnel.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	oldDB, oldTenant, oldUser := global.GWAF_LOCAL_DB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_LOCAL_DB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE = db, "tunnel-tenant", "tunnel-user"
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldDB, oldTenant, oldUser
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	if err := db.AutoMigrate(&model.Tunnel{}); err != nil {
		t.Fatal(err)
	}
	for _, row := range []model.Tunnel{
		{BaseOrm: baseorm.BaseOrm{Id: "local", Tenant_ID: "tunnel-tenant", USER_CODE: "tunnel-user"}, Name: "Local"},
		{BaseOrm: baseorm.BaseOrm{Id: "other-user", Tenant_ID: "tunnel-tenant", USER_CODE: "other"}, Name: "Other User"},
		{BaseOrm: baseorm.BaseOrm{Id: "other-tenant", Tenant_ID: "other", USER_CODE: "tunnel-user"}, Name: "Other Tenant"},
	} {
		if err := db.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Model(&model.Tunnel{}).Where("id = ?", "local").Updates(map[string]any{"region_protection": nil, "ddns_protection": nil}).Error; err != nil {
		t.Fatal(err)
	}
	return db
}

func TestTunnelProtectionIndependentCASAndScope(t *testing.T) {
	setupTunnelProtectionTest(t)
	ctx := context.Background()
	svc := WafTunnelServiceApp
	initial, err := svc.GetProtection(ctx, "local")
	if err != nil || initial.Region.Enabled || initial.Region.Fallback != "allow" || initial.Region.Unknown != "allow" || initial.Region.Rules == nil || initial.DDNS.Bindings == nil {
		t.Fatalf("legacy defaults=%+v, %v", initial, err)
	}
	region := model.TunnelRegionProtection{Enabled: true, Unknown: "deny", Fallback: "allow", Rules: []model.TunnelRegionRule{{Name: "中国来源", Operator: "eq", Country: "CN", Action: "allow", Enabled: true}}}
	ddns := model.TunnelDDNSProtection{Bindings: []model.TunnelDDNSBinding{{Domain: "home.example.net", Family: "ipv4", Enabled: true}}}
	for _, id := range []string{"other-user", "other-tenant"} {
		if _, err := svc.GetProtection(ctx, id); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("scope read %s: %v", id, err)
		}
		if _, _, err := svc.SaveRegionProtection(ctx, id, region); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("scope region %s: %v", id, err)
		}
		if _, _, err := svc.SaveDDNSProtection(ctx, id, ddns, false); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("scope DDNS %s: %v", id, err)
		}
	}
	if _, updated, err := svc.SaveRegionProtection(ctx, "local", region); err != nil || updated.Region.Revision != 1 || !updated.Region.Enabled {
		t.Fatalf("save region=%+v, %v", updated.Region, err)
	}
	if _, _, err := svc.SaveRegionProtection(ctx, "local", region); !errors.Is(err, ErrTunnelProtectionConflict) {
		t.Fatalf("stale region: %v", err)
	}
	if _, updated, err := svc.SaveDDNSProtection(ctx, "local", ddns, false); err != nil || updated.DDNS.Revision != 1 || len(updated.DDNS.Bindings) != 1 || updated.DDNS.Bindings[0].ID == "" || updated.Region.Revision != 1 {
		t.Fatalf("save DDNS=%+v, %v", updated.DDNS, err)
	}
	if _, _, err := svc.SaveDDNSProtection(ctx, "local", ddns, false); !errors.Is(err, ErrTunnelProtectionConflict) {
		t.Fatalf("stale DDNS: %v", err)
	}
	if err := svc.ModifyApi(request.WafTunnelEditReq{Id: "local", Name: "Renamed"}); err != nil {
		t.Fatal(err)
	}
	updated, err := svc.GetProtection(ctx, "local")
	if err != nil || updated.Tunnel.Name != "Renamed" || updated.Region.Revision != 1 || updated.DDNS.Revision != 1 {
		t.Fatalf("legacy edit cleared protection: %+v, %v", updated, err)
	}
}

func TestTunnelProtectionConfirmLastEnabledBinding(t *testing.T) {
	db := setupTunnelProtectionTest(t)
	ctx := context.Background()
	svc := WafTunnelServiceApp
	ddns := model.TunnelDDNSProtection{Bindings: []model.TunnelDDNSBinding{{Domain: "home.example.net", Family: "both", Enabled: true}}}
	_, initial, err := svc.SaveDDNSProtection(ctx, "local", ddns, false)
	if err != nil {
		t.Fatal(err)
	}
	changed := initial.DDNS
	changed.Bindings[0].Enabled = false
	if _, _, err := svc.SaveDDNSProtection(ctx, "local", changed, false); !errors.Is(err, ErrTunnelWhitelistConfirm) {
		t.Fatalf("disable last binding without confirmation: %v", err)
	}
	changed.Bindings[0].Enabled = true
	changed.Bindings[0].ID = "another-binding"
	if _, _, err := svc.SaveDDNSProtection(ctx, "local", changed, true); !errors.Is(err, ErrTunnelDDNSBinding) {
		t.Fatalf("unknown binding ID: %v", err)
	}
	clear := model.TunnelDDNSProtection{Revision: 1, Bindings: []model.TunnelDDNSBinding{}}
	if _, _, err := svc.SaveDDNSProtection(ctx, "local", clear, false); !errors.Is(err, ErrTunnelWhitelistConfirm) {
		t.Fatalf("delete last binding without confirmation: %v", err)
	}
	if _, after, err := svc.SaveDDNSProtection(ctx, "local", clear, true); err != nil || after.DDNS.Revision != 2 || HasEnabledTunnelDDNS(after.DDNS.Bindings) {
		t.Fatalf("confirmed deletion: %+v, %v", after.DDNS, err)
	}
	if err := db.Model(&model.Tunnel{}).Where("id = ?", "local").Update("allow_ip", "198.51.100.0/24").Error; err != nil {
		t.Fatal(err)
	}
	ddns.Revision = 2
	if _, _, err := svc.SaveDDNSProtection(ctx, "local", ddns, false); err != nil {
		t.Fatal(err)
	}
	clear.Revision = 3
	if _, after, err := svc.SaveDDNSProtection(ctx, "local", clear, false); err != nil || after.Tunnel.AllowIp != "198.51.100.0/24" {
		t.Fatalf("valid static allowlist retained: %+v, %v", after, err)
	}
}
