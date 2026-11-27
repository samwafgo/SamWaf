//go:build linux

package waf_service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"SamWaf/firewall"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	pg "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestSystemBanEBPFPostgresLifecycle 在隔离网络和专用 PostgreSQL 中走真实服务层，不只检查 map 内容。
func TestSystemBanEBPFPostgresLifecycle(t *testing.T) {
	dsn := os.Getenv("SAMWAF_TEST_PG_CACHE_DSN")
	if os.Getenv("SAMWAF_TEST_EBPF") != "isolated-netns" || dsn == "" {
		t.Skip("requires an isolated netns and dedicated PostgreSQL database")
	}
	t.Setenv("SAMWAF_BPF_STATE_DIR", t.TempDir())
	pinRoot := fmt.Sprintf("/sys/fs/bpf/samwaf-service-test-%d", time.Now().UnixNano())
	t.Setenv("SAMWAF_BPF_PIN_ROOT", pinRoot)
	db, err := gorm.Open(pg.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AutoMigrate(&model.FirewallIPBlock{}); err != nil {
		t.Fatal(err)
	}
	previous := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = db
	t.Cleanup(func() { global.GWAF_LOCAL_DB = previous; raw, _ := db.DB(); raw.Close() })
	t.Cleanup(func() { _ = firewall.DetachBPF(true) })
	service := WafFirewallIPBlockServiceApp
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	probe := func(source string, want bool) {
		t.Helper()
		local := &net.UDPAddr{IP: net.ParseIP(source)}
		remote := listener.LocalAddr().(*net.UDPAddr)
		client, err := net.DialUDP("udp4", local, remote)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		_ = listener.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
		_, err = client.Write([]byte("system-probe"))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = listener.ReadFrom(make([]byte, 32))
		if (err == nil) != want {
			t.Fatalf("source=%s delivered=%v want %v: %v", source, err == nil, want, err)
		}
	}
	probe("127.0.0.2", true)
	if err = service.AddApi(request.WafFirewallIPBlockAddReq{IP: "127.0.0.2", Reason: "test", ExpireTime: time.Now().Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	probe("127.0.0.2", false)
	var row model.FirewallIPBlock
	if err = db.Where("ip=?", "127.0.0.2").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if err = service.DisableApi(request.WafFirewallIPBlockDisableReq{Id: row.Id}); err != nil {
		t.Fatal(err)
	}
	probe("127.0.0.2", true)
	if err = service.EnableApi(request.WafFirewallIPBlockEnableReq{Id: row.Id}); err != nil {
		t.Fatal(err)
	}
	probe("127.0.0.2", false)
	if err = service.ModifyApi(request.WafFirewallIPBlockEditReq{Id: row.Id, IP: "127.0.0.3", Reason: "moved", Status: "active", ExpireTime: row.ExpireTime}); err != nil {
		t.Fatal(err)
	}
	probe("127.0.0.2", true)
	probe("127.0.0.3", false)
	// 写库失败发生在内核发布之前，原有效策略与数据库状态都必须保持。
	if err = db.Callback().Update().Before("gorm:update").Register("test:fail-system-update", func(tx *gorm.DB) { tx.AddError(errors.New("injected write failure")) }); err != nil {
		t.Fatal(err)
	}
	if err = service.DisableApi(request.WafFirewallIPBlockDisableReq{Id: row.Id}); err == nil {
		t.Fatal("failed SQL update reported success")
	}
	_ = db.Callback().Update().Remove("test:fail-system-update")
	probe("127.0.0.3", false)
	// 控制账本故障发生在事务已修改 SQL、尚未发布内核时，不能提交假 inactive。
	statePath := filepath.Join(os.Getenv("SAMWAF_BPF_STATE_DIR"), "state.json")
	state, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(statePath, []byte("invalid ledger"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = service.DisableApi(request.WafFirewallIPBlockDisableReq{Id: row.Id}); err == nil {
		t.Fatal("failed kernel publication reported success")
	}
	probe("127.0.0.3", false)
	var current model.FirewallIPBlock
	if err = db.Where("id=?", row.Id).First(&current).Error; err != nil || current.Status != "active" {
		t.Fatalf("failed publication committed fake state: %+v %v", current, err)
	}
	if err = os.WriteFile(statePath, state, 0600); err != nil {
		t.Fatal(err)
	}
	if err = PeriodicSystemBanReconcile(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	// 删除手工记录不能撤销独立来源的同 IP 封禁。
	var fw firewall.FireWallEngine
	if err = fw.RestoreIPSet("independent", []string{"127.0.0.3"}); err != nil {
		t.Fatal(err)
	}
	if err = service.DelApi(request.WafFirewallIPBlockDelReq{Id: row.Id}); err != nil {
		t.Fatal(err)
	}
	probe("127.0.0.3", false)
	if err = fw.DestroyIPSet("independent"); err != nil {
		t.Fatal(err)
	}
	probe("127.0.0.3", true)
	if err = service.AddApi(request.WafFirewallIPBlockAddReq{IP: "127.0.0.2", ExpireTime: time.Now().Add(2 * time.Second).Unix()}); err != nil {
		t.Fatal(err)
	}
	probe("127.0.0.2", false)
	time.Sleep(2100 * time.Millisecond)
	probe("127.0.0.2", true)
	if _, err = service.ClearExpiredRules(); err != nil {
		t.Fatal(err)
	}
	if err = service.AddApi(request.WafFirewallIPBlockAddReq{IP: "127.0.0.2"}); err != nil {
		t.Fatal(err)
	}
	probe("127.0.0.2", false)
	// 用新的 pin 根模拟重启后内核对象丢失；恢复必须依据数据库/原期限重新建立实际封禁。
	if err = firewall.DetachBPF(true); err != nil {
		t.Fatal(err)
	}
	if err = os.Setenv("SAMWAF_BPF_PIN_ROOT", pinRoot+"-restored"); err != nil {
		t.Fatal(err)
	}
	probe("127.0.0.2", true)
	if err = RestoreSystemBansOnStartup(); err != nil {
		t.Fatal(err)
	}
	probe("127.0.0.2", false)
}
