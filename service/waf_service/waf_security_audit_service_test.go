package waf_service

import (
	"path/filepath"
	"testing"

	"SamWaf/global"
	"SamWaf/model"
	commonreq "SamWaf/model/common/request"
	"SamWaf/model/request"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 统一安全审计表(security_audit_log)用例：Write() 按事件自动分类，GetListApi 支持按分类筛选。

func setupSecurityAuditTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(
		sqlite.Open(filepath.Join(t.TempDir(), "secaudit_test.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
	)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.SecurityAuditLog{}); err != nil {
		t.Fatalf("AutoMigrate 失败: %v", err)
	}
	oldDB, oldTenant, oldUser := global.GWAF_LOCAL_LOG_DB, global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_LOCAL_LOG_DB = db
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "SamWafCom", "user-uuid-secaudit"
	t.Cleanup(func() {
		global.GWAF_LOCAL_LOG_DB = oldDB
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
}

func TestSecurityAudit_WriteAutoCategory(t *testing.T) {
	setupSecurityAuditTestDB(t)

	// access 类事件：登录成功
	WafSecurityAuditServiceApp.Write(AuditEntry{
		Event: model.AccessEventLoginOK, AccountName: "admin",
		Country: "本地", City: "本地", Result: model.AccessAuditOK, Message: "登录成功",
	})
	// config 类事件：SSL 导出落盘
	WafSecurityAuditServiceApp.Write(AuditEntry{
		Event: model.AuditEventConfigSSLExportWrite, AccountName: "admin",
		Country: "本地", City: "本地", Result: model.AccessAuditOK,
		Message: "[systemAdmin] 导出成功: /data/ssl_export/a.crt , /data/ssl_export/a.key",
	})

	// 分类应被自动写对
	var rows []model.SecurityAuditLog
	if err := global.GWAF_LOCAL_LOG_DB.Order("event").Find(&rows).Error; err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("期望 2 条，实际 %d", len(rows))
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.Event] = r.Category
	}
	if got[model.AccessEventLoginOK] != model.AuditCategoryAccess {
		t.Fatalf("login_ok 应归 access，实际 %q", got[model.AccessEventLoginOK])
	}
	if got[model.AuditEventConfigSSLExportWrite] != model.AuditCategoryConfig {
		t.Fatalf("ssl_export 应归 config，实际 %q", got[model.AuditEventConfigSSLExportWrite])
	}
	// 审计 Message 不得含密钥材料（这里只放了路径，回归防呆）
	for _, r := range rows {
		if containsKeyMaterial(r.Message) {
			t.Fatalf("审计 Message 疑似含密钥材料: %q", r.Message)
		}
	}
}

func TestSecurityAudit_GetListFilterByCategory(t *testing.T) {
	setupSecurityAuditTestDB(t)
	for _, e := range []string{model.AccessEventLoginOK, model.AccessEventLoginFail} {
		WafSecurityAuditServiceApp.Write(AuditEntry{Event: e, Country: "本地", City: "本地"})
	}
	WafSecurityAuditServiceApp.Write(AuditEntry{Event: model.AuditEventConfigSSLExportWrite, Country: "本地", City: "本地"})

	// 只要 config 类
	list, total, err := WafSecurityAuditServiceApp.GetListApi(request.WafAccessAuditSearchReq{
		Category: model.AuditCategoryConfig, PageInfo: commonreq.PageInfo{PageIndex: 1, PageSize: 10},
	})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if total != 1 || len(list) != 1 || list[0].Event != model.AuditEventConfigSSLExportWrite {
		t.Fatalf("按 config 分类筛选结果不对: total=%d list=%+v", total, list)
	}

	// 不带分类 = 全部
	_, totalAll, _ := WafSecurityAuditServiceApp.GetListApi(request.WafAccessAuditSearchReq{PageInfo: commonreq.PageInfo{PageIndex: 1, PageSize: 10}})
	if totalAll != 3 {
		t.Fatalf("不带分类应返回全部 3 条，实际 %d", totalAll)
	}
}

func containsKeyMaterial(s string) bool {
	for _, marker := range []string{"PRIVATE KEY", "BEGIN CERTIFICATE"} {
		if len(s) >= len(marker) && contains(s, marker) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
