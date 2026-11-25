package waf_service

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
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

func TestSecurityAudit_ObjectFilters(t *testing.T) {
	setupSecurityAuditTestDB(t)
	svc := WafSecurityAuditServiceApp
	for _, object := range []struct{ kind, id string }{
		{"tunnel", "feature-1"}, {"tunnel", "feature-10"}, {"tunnel-group", "feature-1"}, {"", ""},
	} {
		svc.Write(AuditEntry{Event: model.AuditEventConfigTunnelDDNS, ObjectType: object.kind, ObjectID: object.id})
	}
	for i, scope := range []baseorm.BaseOrm{
		{Id: "other-tenant", Tenant_ID: "other", USER_CODE: global.GWAF_USER_CODE},
		{Id: "other-user", Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: "other"},
	} {
		if err := global.GWAF_LOCAL_LOG_DB.Create(&model.SecurityAuditLog{
			BaseOrm: scope, Category: model.AuditCategoryConfig, Event: model.AuditEventConfigTunnelDDNS,
			ObjectType: "tunnel", ObjectID: "feature-1",
		}).Error; err != nil {
			t.Fatalf("seed out-of-scope row %d: %v", i, err)
		}
	}
	for _, tt := range []struct {
		kind, id string
		want     int64
	}{
		{"tunnel", "feature-1", 1}, {"", "feature-1", 2}, {"tunnel", "", 2},
		{"tunnel", "feature-%", 0}, {"tunnel%", "", 0}, {"", "", 4},
	} {
		t.Run(tt.kind+"/"+tt.id, func(t *testing.T) {
			list, total, err := svc.GetListApi(request.WafAccessAuditSearchReq{
				Category: model.AuditCategoryConfig, Event: model.AuditEventConfigTunnelDDNS,
				ObjectType: tt.kind, ObjectID: tt.id, PageInfo: commonreq.PageInfo{PageIndex: 1, PageSize: 1},
			})
			if err != nil || total != tt.want || len(list) != min(1, int(tt.want)) {
				t.Fatalf("query got total=%d page=%d err=%v; want total=%d", total, len(list), err, tt.want)
			}
		})
	}
}

func TestSecurityAudit_TunnelConfigDetail(t *testing.T) {
	setupSecurityAuditTestDB(t)
	svc := WafSecurityAuditServiceApp
	tunnel := model.Tunnel{BaseOrm: baseorm.BaseOrm{Id: "stable-id"}, Code: "changed-code", SSLCertificateKey: "private-marker"}
	before := model.TunnelRegionProtection{Enabled: true, Fallback: "allow", Unknown: "deny", Rules: []model.TunnelRegionRule{
		{Name: "先处理", Country: "CN", Operator: "eq", Action: "deny", Enabled: true},
		{Name: "再处理", Country: "US", Operator: "ne", Action: "allow", Enabled: false},
	}}
	after := before
	after.Fallback = "deny"
	after.Rules = []model.TunnelRegionRule{before.Rules[1], before.Rules[0]}
	svc.WriteTunnelConfig("admin", "192.0.2.1", tunnel, model.AuditEventConfigTunnelRegion, "edit",
		&TunnelAuditState{Region: &before, Hostname: "not-recorded.example"}, &TunnelAuditState{Region: &after})
	svc.WriteTunnelConfig("admin", "192.0.2.1", tunnel, model.AuditEventConfigTunnelDDNS, "manual_refresh", nil,
		&TunnelAuditState{BindingID: "binding-1", Hostname: "edge.example.com", Family: "both", Enabled: true})
	const discarded = "audit-test-discarded"
	svc.WriteTunnelConfig("admin", "192.0.2.1", tunnel, model.AuditEventConfigTunnelDDNS, "add", nil,
		&TunnelAuditState{BindingID: "binding-2", Hostname: "https://user:" + discarded + "@example.com", Family: discarded, Addresses: []string{"192.0.2.2", discarded}})
	svc.WriteTunnelConfig("admin", "192.0.2.1", tunnel, model.AuditEventConfigTunnelDDNS, discarded, nil, nil)
	rows := tunnelAuditTestRows(t, "stable-id")
	if len(rows) != 3 {
		t.Fatalf("expected 3 config rows, got %d", len(rows))
	}
	for _, row := range rows {
		if row.AccountName != "admin" || row.ClientIP != "192.0.2.1" || row.URL != "" || row.Result != model.AccessAuditOK || row.Category != model.AuditCategoryConfig {
			t.Fatalf("incorrect audit metadata: %+v", row)
		}
		wire, err := json.Marshal(row)
		if err != nil || !strings.Contains(string(wire), `"detail":{`) {
			t.Fatalf("detail is not a JSON object: %s (%v)", wire, err)
		}
		for _, excluded := range []string{"private-marker", discarded, "not-recorded.example", "changed-code"} {
			if strings.Contains(string(wire), excluded) {
				t.Fatalf("unrelated field in audit: %s", wire)
			}
		}
		detail := tunnelAuditTestDetail(t, row)
		switch detail.Reason {
		case "edit":
			if !reflect.DeepEqual(detail.Before.Region, &before) || !reflect.DeepEqual(detail.After.Region, &after) {
				t.Fatalf("region policy details differ: %s", row.Detail)
			}
		case "manual_refresh":
			if detail.Before != nil || detail.After.BindingID != "binding-1" || detail.After.Hostname != "edge.example.com" || detail.After.Family != "both" || detail.After.Enabled == nil || !*detail.After.Enabled {
				t.Fatalf("manual refresh details differ: %s", row.Detail)
			}
		case "add":
			if detail.Before != nil || detail.After.Enabled == nil || *detail.After.Enabled || !reflect.DeepEqual(*detail.After.Addresses, []string{"192.0.2.2"}) {
				t.Fatalf("binding details differ: %s", row.Detail)
			}
		default:
			t.Fatalf("unexpected reason: %q", detail.Reason)
		}
	}
}

func TestSecurityAudit_TunnelRuntimeTransitions(t *testing.T) {
	setupSecurityAuditTestDB(t)
	svc := new(WafSecurityAuditService)
	tunnel := model.Tunnel{BaseOrm: baseorm.BaseOrm{Id: "tunnel-1"}}
	binding := model.TunnelDDNSBinding{ID: "binding-1", Domain: "edge.example.com", Family: "both", Enabled: true}
	first := []string{"192.0.2.1", "2001:db8::1"}
	canonical := []string{"2001:0db8::1", "::ffff:192.0.2.1", "192.0.2.1"}
	write := func(reason string, before, after []string) {
		svc.WriteTunnelDDNSRuntime(tunnel, binding, reason, before, after)
	}
	write("addresses_changed", nil, first)
	write("addresses_changed", nil, canonical)   //同一变化重复上报
	write("addresses_changed", first, canonical) //集合未变
	write("resolution_error", first, first)
	write("resolution_error", canonical, canonical)
	write("expired", first, nil)
	write("resolution_recovered", nil, first)
	write("resolution_error", first, first) //恢复后再次进入错误状态
	write("ignored", first, nil)

	rows := tunnelAuditTestRows(t, tunnel.Id)
	reasons := map[string]int{}
	for _, row := range rows {
		detail := tunnelAuditTestDetail(t, row)
		reasons[detail.Reason]++
		if row.Category != model.AuditCategoryConfig || row.AccountName != "system" || row.ClientIP != "" || row.URL != "" {
			t.Fatalf("incorrect system audit metadata: %+v", row)
		}
		if detail.Before.BindingID != binding.ID || detail.After.Hostname != binding.Domain {
			t.Fatalf("missing binding identity: %s", row.Detail)
		}
		wantEvent, wantResult := model.AuditEventConfigTunnelDDNSResolution, model.AccessAuditOK
		switch detail.Reason {
		case "addresses_changed":
			wantEvent = model.AuditEventConfigTunnelDDNSAddresses
		case "expired":
			if !reflect.DeepEqual(*detail.Before.Addresses, first) || !reflect.DeepEqual(*detail.After.Addresses, []string{}) {
				t.Fatalf("incorrect expiry before/after: %s", row.Detail)
			}
			wantResult = model.AccessAuditFail
		case "resolution_error":
			wantResult = model.AccessAuditFail
		}
		if row.Event != wantEvent || row.Result != wantResult {
			t.Fatalf("incorrect event/result for %s: %+v", detail.Reason, row)
		}
	}
	if want := (map[string]int{"addresses_changed": 1, "resolution_error": 2, "expired": 1, "resolution_recovered": 1}); !reflect.DeepEqual(reasons, want) {
		t.Fatalf("got reason counts %v; want %v", reasons, want)
	}
}

func TestSecurityAudit_TunnelDDNSDuplicateWindow(t *testing.T) {
	svc := new(WafSecurityAuditService)
	now := time.Now()
	sample := []byte(`{"reason":"resolution_error"}`)
	var attempts int
	write := func() error {
		attempts++
		if attempts == 1 {
			return errors.New("write unavailable")
		}
		return nil
	}
	for _, tt := range []struct {
		delay        time.Duration
		wantAttempts int
		wantError    bool
	}{
		{0, 1, true}, {time.Second, 2, false}, {2 * time.Second, 2, false},
		{time.Second + tunnelAuditRepeatWindow, 3, false},
	} {
		err := svc.writeTunnelDDNSTransition("tunnel-1", "binding-1", sample, now.Add(tt.delay), write)
		if (err != nil) != tt.wantError || attempts != tt.wantAttempts {
			t.Fatalf("delay %v: attempts=%d, err=%v; want attempts=%d, error=%v", tt.delay, attempts, err, tt.wantAttempts, tt.wantError)
		}
	}
}

func TestSecurityAudit_TunnelRuntimeRetryPreservesRowID(t *testing.T) {
	setupSecurityAuditTestDB(t)
	svc := new(WafSecurityAuditService)
	tunnel := model.Tunnel{BaseOrm: baseorm.BaseOrm{Id: "tunnel-1"}}
	binding := model.TunnelDDNSBinding{ID: "binding-1", Enabled: true}
	var ids []string
	if err := global.GWAF_LOCAL_LOG_DB.Callback().Create().After("gorm:commit_or_rollback_transaction").Register("test:audit-write-ack", func(db *gorm.DB) {
		row := db.Statement.Dest.(*model.SecurityAuditLog)
		ids = append(ids, row.Id)
		if deadline, ok := db.Statement.Context.Deadline(); !ok || time.Until(deadline) > tunnelAuditRuntimeWait {
			t.Errorf("runtime audit deadline not bounded: %v", deadline)
		}
		if len(ids) == 1 {
			_ = db.AddError(errors.New("simulated lost commit acknowledgement"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	svc.WriteTunnelDDNSRuntime(tunnel, binding, "resolution_error", nil, nil)
	svc.WriteTunnelDDNSRuntime(tunnel, binding, "resolution_error", nil, nil)
	rows := tunnelAuditTestRows(t, tunnel.Id)
	if len(ids) != 2 || ids[0] != ids[1] || len(rows) != 1 || rows[0].Id != ids[0] {
		t.Fatalf("expected two create attempts with one row: ids=%v rows=%+v", ids, rows)
	}
}

func TestSecurityAudit_TunnelDetailBounds(t *testing.T) {
	region := &model.TunnelRegionProtection{Fallback: "allow", Unknown: "deny"}
	for range tunnelAuditMaxRules + 1 {
		region.Rules = append(region.Rules, model.TunnelRegionRule{Name: strings.Repeat("<", 60) + "\nextra", Country: "CN", Operator: "eq", Action: "deny"})
	}
	state := &TunnelAuditState{Region: region}
	encoded := newTunnelAuditDetail("edit", state, state, true).marshal()
	detail := tunnelAuditTestDetail(t, model.SecurityAuditLog{Detail: encoded})
	if len(encoded) > tunnelAuditMaxDetail || !detail.Truncated || len(detail.After.Region.Rules) == 0 || len(detail.After.Region.Rules) > tunnelAuditMaxRules || detail.After.Region.Rules[0].Name != strings.Repeat("<", 60) {
		t.Fatalf("oversized/invalid region detail: bytes=%d rules=%d truncated=%v", len(encoded), len(detail.After.Region.Rules), detail.Truncated)
	}
	var addresses []string
	for i := 0; i < tunnelAuditMaxAddresses+1; i++ {
		addresses = append(addresses, fmt.Sprintf("192.0.2.%d", i))
	}
	encoded = newTunnelAuditDetail("addresses_changed", nil, &TunnelAuditState{Addresses: addresses}, false).marshal()
	detail = tunnelAuditTestDetail(t, model.SecurityAuditLog{Detail: encoded})
	if len(encoded) > tunnelAuditMaxDetail || !detail.Truncated || len(*detail.After.Addresses) != tunnelAuditMaxAddresses {
		t.Fatalf("oversized/invalid addresses detail: bytes=%d addresses=%d truncated=%v", len(encoded), len(*detail.After.Addresses), detail.Truncated)
	}
}

func tunnelAuditTestRows(t *testing.T, tunnelID string) []model.SecurityAuditLog {
	t.Helper()
	list, total, err := WafSecurityAuditServiceApp.GetListApi(request.WafAccessAuditSearchReq{
		ObjectType: model.AuditObjectTypeTunnel, ObjectID: tunnelID, PageInfo: commonreq.PageInfo{PageIndex: 1, PageSize: 25},
	})
	if err != nil || int64(len(list)) != total {
		t.Fatalf("query got rows=%d total=%d err=%v", len(list), total, err)
	}
	return list
}

func tunnelAuditTestDetail(t *testing.T, row model.SecurityAuditLog) tunnelAuditDetail {
	t.Helper()
	var detail tunnelAuditDetail
	if err := json.Unmarshal(row.Detail, &detail); err != nil {
		t.Fatalf("decode audit detail %s: %v", row.Detail, err)
	}
	return detail
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
