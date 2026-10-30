package waf_service

import (
	"path/filepath"
	"strings"
	"testing"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafdb/dialect"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupFWBlockTestDB 建临时库并接管全局 DB，用例结束后还原
func setupFWBlockTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	oldDialect := func() (d dialect.DBDialect) {
		defer func() { _ = recover() }()
		return dialect.Get()
	}()
	dialect.Register(&dialect.SQLiteDialect{})
	t.Cleanup(func() { dialect.Register(oldDialect) })
	db, err := gorm.Open(
		sqlite.Open(filepath.Join(t.TempDir(), "fwblock_test.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
	)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.FirewallIPBlock{}); err != nil {
		t.Fatalf("AutoMigrate 失败: %v", err)
	}

	oldDB, oldTenant, oldUser := global.GWAF_LOCAL_DB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_LOCAL_DB = db
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "SamWafCom", "user-uuid-fwblock"
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB = oldDB
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func newFWBlockBase(id string) baseorm.BaseOrm {
	return baseorm.BaseOrm{Id: id, USER_CODE: global.GWAF_USER_CODE, Tenant_ID: global.GWAF_TENANT_ID}
}

// 全网/不支持的写法必须在写入系统防火墙之前被挡下。
// 校验前置在 CheckAvailable 之前，因此本用例不需要真实防火墙环境。
// 反向验证：把 validateBlockIP 里的 IsBlockAllIPPattern 判断去掉，本用例必须变红。
func TestFirewallBlockAddRejectsInvalidTarget(t *testing.T) {
	setupFWBlockTestDB(t)

	cases := map[string]string{
		"0.0.0.0/0":               "全网 IPv4",
		"::/0":                    "全网 IPv6",
		"1.2.3.4/0":               "掩码 /0 语义即全网",
		"*.*.*.*":                 "全通配",
		"0.0.0.0-255.255.255.255": "全空间区间",
		"10.10.*.*":               "通配符：系统防火墙表达不了",
		"1.2.3.4-1.2.3.99":        "区间：系统防火墙表达不了",
		"not-an-ip":               "非法格式",
	}
	for ip, desc := range cases {
		err := WafFirewallIPBlockServiceApp.AddApi(request.WafFirewallIPBlockAddReq{IP: ip, Reason: "test"})
		if err == nil {
			t.Errorf("AddApi(%q) (%s) 应当被拒绝，但通过了", ip, desc)
		}
	}

	// 确认一条库记录都没落（校验必须发生在任何写入之前）
	var cnt int64
	global.GWAF_LOCAL_DB.Model(&model.FirewallIPBlock{}).Count(&cnt)
	if cnt != 0 {
		t.Errorf("被拒绝的目标不应产生任何记录，实际 %d 条", cnt)
	}
}

// 编辑同样不允许把目标改成全网/通配符；存量带站点码的记录在编辑时归一为空串（全局）。
func TestFirewallBlockModifyValidatesAndNormalizes(t *testing.T) {
	db := setupFWBlockTestDB(t)
	db.Create(&model.FirewallIPBlock{
		BaseOrm: newFWBlockBase("f1"), HostCode: "legacy-host", IP: "1.2.3.4",
		Reason: "r", BlockType: "manual", Status: "active",
	})

	// 改成全网/通配符必须被拒
	for _, ip := range []string{"0.0.0.0/0", "::/0", "10.10.*.*"} {
		err := WafFirewallIPBlockServiceApp.ModifyApi(request.WafFirewallIPBlockEditReq{
			Id: "f1", IP: ip, Reason: "r", Status: "active",
		})
		if err == nil {
			t.Errorf("ModifyApi 目标改为 %q 应当被拒绝", ip)
		}
	}

	// 合法编辑（IP 不变，不触发防火墙调用）：host_code 归一为空串
	err := WafFirewallIPBlockServiceApp.ModifyApi(request.WafFirewallIPBlockEditReq{
		Id: "f1", HostCode: "some-host", IP: "1.2.3.4", Reason: "r2", Status: "active",
	})
	if err != nil {
		t.Fatalf("合法编辑不应报错: %v", err)
	}
	var bean model.FirewallIPBlock
	db.Where("id = ?", "f1").First(&bean)
	if bean.HostCode != "" {
		t.Errorf("编辑后 host_code 应归一为空串，实际 %q", bean.HostCode)
	}
	if bean.Reason != "r2" {
		t.Errorf("编辑后 reason 应为 r2，实际 %q", bean.Reason)
	}
}

// 错误文案必须向用户说明「全网封禁会连管理端一起挡住」，而不是一句干巴巴的「不合法」
func TestFirewallBlockLegacyTargets(t *testing.T) {
	db := setupFWBlockTestDB(t)
	for i, ip := range []string{"0.0.0.0/0", "::/0", "10.*.*.*"} {
		id := []string{"legacy-v4", "legacy-v6", "legacy-wildcard"}[i]
		bean := model.FirewallIPBlock{BaseOrm: newFWBlockBase(id), IP: ip, Status: "inactive"}
		if err := db.Create(&bean).Error; err != nil {
			t.Fatal(err)
		}
		err := WafFirewallIPBlockServiceApp.EnableApi(request.WafFirewallIPBlockEnableReq{Id: id})
		if err == nil || (!strings.Contains(err.Error(), "管理端") && !strings.Contains(err.Error(), "单个IP")) {
			t.Fatalf("legacy target must fail validation: %v", err)
		}
		if err := db.Where("id = ?", id).First(&bean).Error; err != nil || bean.Status != "inactive" {
			t.Fatalf("rejected enable changed record: %+v, %v", bean, err)
		}
		if err := db.Model(&model.FirewallIPBlock{}).Where("id = ?", id).Update("status", "active").Error; err != nil {
			t.Fatal(err)
		}
	}
	success, failed, err := WafFirewallIPBlockServiceApp.SyncFirewallRules("")
	if err != nil || success != 0 || failed != 3 {
		t.Fatalf("sync invalid targets: success=%d failed=%d err=%v", success, failed, err)
	}
}

func TestFirewallBlockAddErrorMessageMentionsLockout(t *testing.T) {
	setupFWBlockTestDB(t)
	err := WafFirewallIPBlockServiceApp.AddApi(request.WafFirewallIPBlockAddReq{IP: "0.0.0.0/0"})
	if err == nil || !strings.Contains(err.Error(), "管理端") {
		t.Errorf("全网封禁的错误文案应提示管理端风险，实际: %v", err)
	}
}
