package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafdb/dialect"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
)

func setupNotifySubTestDBs(t *testing.T) (*gorm.DB, *gorm.DB) {
	t.Helper()
	dir := t.TempDir()
	coreDB, err := gorm.Open(sqlite.Open(filepath.Join(dir, "core.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	logDB, err := gorm.Open(sqlite.Open(filepath.Join(dir, "log.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := coreDB.AutoMigrate(&model.NotifyChannel{}, &model.NotifySubscription{}, &model.SystemConfig{}); err != nil {
		t.Fatal(err)
	}
	if err := logDB.AutoMigrate(&model.NotifyLog{}); err != nil {
		t.Fatal(err)
	}

	oldCore, oldLog := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB
	oldTenant, oldUser := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	oldAllowed := global.GCONFIG_OUTBOUND_ALLOWED_HOSTS
	oldNoticeTitle := global.GWAF_NOTICE_TITLE
	var prevDialect dialect.DBDialect
	func() {
		defer func() { _ = recover() }()
		prevDialect = dialect.Get()
	}()
	dialect.Register(&dialect.SQLiteDialect{})

	global.GWAF_LOCAL_DB = coreDB
	global.GWAF_LOCAL_LOG_DB = logDB
	global.GWAF_TENANT_ID = "tenantA"
	global.GWAF_USER_CODE = "userA"
	global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = "127.0.0.1"
	global.GWAF_NOTICE_TITLE = "Node1"

	WafNotifyThrottleServiceApp.ResetAll()
	t.Cleanup(func() {
		WafNotifyThrottleServiceApp.ResetAll()
		dialect.Register(prevDialect)
		global.GWAF_LOCAL_DB = oldCore
		global.GWAF_LOCAL_LOG_DB = oldLog
		global.GWAF_TENANT_ID = oldTenant
		global.GWAF_USER_CODE = oldUser
		global.GCONFIG_OUTBOUND_ALLOWED_HOSTS = oldAllowed
		global.GWAF_NOTICE_TITLE = oldNoticeTitle
		if sqlDB, err := coreDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
		if sqlDB, err := logDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return coreDB, logDB
}

func TestDedupSubscriptionsByChannel(t *testing.T) {
	subs := []model.NotifySubscription{
		{BaseOrm: baseorm.BaseOrm{Id: "sub-new"}, ChannelId: "ch-1", MessageType: model.MSG_TYPE_ATTACK_INFO},
		{BaseOrm: baseorm.BaseOrm{Id: "sub-old"}, ChannelId: "ch-1", MessageType: model.MSG_TYPE_ATTACK_INFO},
		{BaseOrm: baseorm.BaseOrm{Id: "sub-other"}, ChannelId: "ch-2", MessageType: model.MSG_TYPE_ATTACK_INFO},
	}
	got := dedupSubscriptionsByChannel(subs)
	if len(got) != 2 || got[0].Id != "sub-new" || got[1].Id != "sub-other" {
		t.Fatalf("unexpected dedup result: %+v", got)
	}
}

func TestSendEventDedupsDuplicateChannelSubscriptionsAndRendersTitleLocation(t *testing.T) {
	coreDB, logDB := setupNotifySubTestDBs(t)

	var delivered int32
	var lastText, lastTitle string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&delivered, 1)
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Markdown map[string]string `json:"markdown"`
		}
		_ = json.Unmarshal(body, &payload)
		lastTitle = payload.Markdown["title"]
		lastText = payload.Markdown["text"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	t.Cleanup(srv.Close)

	now := customtype.JsonTime(time.Now())
	earlier := customtype.JsonTime(time.Now().Add(-10 * time.Minute))

	ch := model.NotifyChannel{
		BaseOrm:    baseorm.BaseOrm{Id: "ch-ding", Tenant_ID: "tenantA", USER_CODE: "userA", CREATE_TIME: earlier, UPDATE_TIME: earlier},
		Name:       "钉钉告警",
		Type:       "dingtalk",
		WebhookURL: srv.URL,
		Status:     1,
	}
	if err := coreDB.Create(&ch).Error; err != nil {
		t.Fatal(err)
	}

	// 故意在未建唯一索引的测试库里插入两条同渠道同类型订阅，模拟旧库脏数据
	oldSub := model.NotifySubscription{
		BaseOrm:         baseorm.BaseOrm{Id: "sub-old", Tenant_ID: "tenantA", USER_CODE: "userA", CREATE_TIME: earlier, UPDATE_TIME: earlier},
		ChannelId:       ch.Id,
		MessageType:     model.MSG_TYPE_ATTACK_INFO,
		Status:          1,
		ThrottleMode:    model.ThrottleModeRealtime,
		ContentTemplate: "OLD_TPL {{.AttackType}}",
	}
	newSub := model.NotifySubscription{
		BaseOrm:         baseorm.BaseOrm{Id: "sub-new", Tenant_ID: "tenantA", USER_CODE: "userA", CREATE_TIME: now, UPDATE_TIME: now},
		ChannelId:       ch.Id,
		MessageType:     model.MSG_TYPE_ATTACK_INFO,
		Status:          1,
		ThrottleMode:    model.ThrottleModeRealtime,
		TitleTemplate:   "自定义攻击标题",
		ContentTemplate: "**域名:** {{.Domain}}\n\n**攻击IP:** {{.Ip}} ({{.Location}})",
	}
	if err := coreDB.Create(&oldSub).Error; err != nil {
		t.Fatal(err)
	}
	if err := coreDB.Create(&newSub).Error; err != nil {
		t.Fatal(err)
	}

	WafNotifySenderServiceApp.SendMessageInfo(innerbean.AttackInfoMessageInfo{
		BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "攻击信息", Server: "waf-1"},
		Domain:          "https://xxxx.com",
		AttackType:      "目录穿越漏洞",
		Url:             "/WEB-INF/web.xml",
		Ip:              "198.51.100.25",
		Location:        "中国 广东 深圳 电信",
		Time:            "2026-11-28 23:00:00",
	})

	if got := atomic.LoadInt32(&delivered); got != 1 {
		t.Fatalf("delivered count = %d, want 1", got)
	}
	if lastTitle != "[Node1] 自定义攻击标题" {
		t.Fatalf("dingtalk markdown.title = %q, want %q", lastTitle, "[Node1] 自定义攻击标题")
	}
	if !strings.HasPrefix(lastText, "### [Node1] 自定义攻击标题\n\n") {
		t.Fatalf("dingtalk markdown.text missing title: %q", lastText)
	}
	if !strings.Contains(lastText, "**域名:** xxxx.com") || !strings.Contains(lastText, "198.51.100.25 (中国 广东 深圳 电信)") {
		t.Fatalf("dingtalk markdown.text did not use newest template with location: %q", lastText)
	}
	if strings.Contains(lastText, "OLD_TPL") {
		t.Fatalf("stale duplicate subscription was mistakenly delivered: %q", lastText)
	}

	var logs []model.NotifyLog
	if err := logDB.Find(&logs).Error; err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 {
		t.Fatalf("notify_logs count = %d, want 1", len(logs))
	}
	if strings.HasPrefix(logs[0].MessageContent, "### ") {
		t.Fatalf("notify_logs.message_content should not duplicate title heading: %q", logs[0].MessageContent)
	}
}

func TestSubscriptionWriteGuardAndTenantIsolation(t *testing.T) {
	coreDB, _ := setupNotifySubTestDBs(t)
	if err := coreDB.Exec("CREATE UNIQUE INDEX uni_notify_sub_tenant_user_ch_type ON notify_subscriptions (tenant_id, user_code, channel_id, message_type)").Error; err != nil {
		t.Fatal(err)
	}

	if err := WafNotifySubscriptionServiceApp.AddApi(request.WafNotifySubscriptionAddReq{
		ChannelId: "ch-1", MessageType: model.MSG_TYPE_ATTACK_INFO, Status: 1,
	}); err != nil {
		t.Fatalf("first AddApi failed: %v", err)
	}
	if err := WafNotifySubscriptionServiceApp.AddApi(request.WafNotifySubscriptionAddReq{
		ChannelId: "ch-1", MessageType: model.MSG_TYPE_ATTACK_INFO, Status: 1,
	}); !errors.Is(err, ErrNotifySubscriptionExists) {
		t.Fatalf("duplicate AddApi err = %v, want ErrNotifySubscriptionExists", err)
	}

	// 另一租户同主键/同渠道数据不应受 tenantA 写操作影响
	other := model.NotifySubscription{
		BaseOrm:         baseorm.BaseOrm{Id: "other-tenant-sub", Tenant_ID: "tenantB", USER_CODE: "userB"},
		ChannelId:       "ch-1",
		MessageType:     model.MSG_TYPE_ATTACK_INFO,
		Status:          1,
		ContentTemplate: "tenantB-keep",
	}
	if err := coreDB.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	_ = WafNotifySubscriptionServiceApp.SaveConfigApi(other.Id, model.ThrottleModeRealtime, "", "", "", "hacked")
	_ = WafNotifySubscriptionServiceApp.DelApi(request.WafNotifySubscriptionDelReq{Id: other.Id})

	var check model.NotifySubscription
	if err := coreDB.Where("id = ?", other.Id).First(&check).Error; err != nil {
		t.Fatalf("other tenant row was deleted across tenants: %v", err)
	}
	if check.ContentTemplate != "tenantB-keep" {
		t.Fatalf("other tenant row was modified across tenants: %q", check.ContentTemplate)
	}

	// ModifyApi 改绑冲突必须返回 ErrNotifySubscriptionExists
	if err := WafNotifySubscriptionServiceApp.AddApi(request.WafNotifySubscriptionAddReq{
		ChannelId: "ch-1", MessageType: model.MSG_TYPE_RULE_TRIGGER, Status: 1,
	}); err != nil {
		t.Fatal(err)
	}
	var ruleSub model.NotifySubscription
	if err := coreDB.Where("tenant_id = ? and message_type = ?", "tenantA", model.MSG_TYPE_RULE_TRIGGER).First(&ruleSub).Error; err != nil {
		t.Fatal(err)
	}
	if err := WafNotifySubscriptionServiceApp.CheckIsExistExcludeId(ruleSub.Id, "ch-1", model.MSG_TYPE_ATTACK_INFO); err != nil {
		t.Fatalf("CheckIsExistExcludeId should detect conflict, got err=%v", err)
	}
	if err := WafNotifySubscriptionServiceApp.ModifyApi(request.WafNotifySubscriptionEditReq{
		Id: ruleSub.Id, ChannelId: "ch-1", MessageType: model.MSG_TYPE_ATTACK_INFO, Status: 1,
	}); !errors.Is(err, ErrNotifySubscriptionExists) {
		t.Fatalf("conflicting ModifyApi err = %v, want ErrNotifySubscriptionExists", err)
	}
}

func TestAttackLocationAndExcludeIPWithLocationSuffix(t *testing.T) {
	// 1. 攻击信息：Vars.Ip 保持纯 IP，Vars.Location 携带归属地，默认正文带归属地且无归属地不拼空括号
	evWithLoc := WafNotifySenderServiceApp.BuildNotifyEvent(innerbean.AttackInfoMessageInfo{
		Domain:     "xxxx.com",
		AttackType: "SQL注入",
		Url:        "/api?id=1",
		Ip:         "198.51.100.8",
		Location:   "中国 浙江 杭州 电信",
		Time:       "2026-11-28 12:00:00",
	})
	if evWithLoc.Vars["Ip"] != "198.51.100.8" || evWithLoc.Vars["Location"] != "中国 浙江 杭州 电信" {
		t.Fatalf("unexpected attack vars: ip=%q loc=%q", evWithLoc.Vars["Ip"], evWithLoc.Vars["Location"])
	}
	if !strings.Contains(evWithLoc.DefaultContent, "198.51.100.8 (中国 浙江 杭州 电信)") {
		t.Fatalf("default content missing formatted IP location: %q", evWithLoc.DefaultContent)
	}
	if MatchNotifyFilter(model.NotifyFilterConfig{ExcludeIps: []string{"198.51.100.0/24"}}, evWithLoc) {
		t.Fatal("CIDR exclude failed for attack event with location")
	}

	evNoLoc := WafNotifySenderServiceApp.BuildNotifyEvent(innerbean.AttackInfoMessageInfo{
		Domain:     "xxxx.com",
		AttackType: "SQL注入",
		Url:        "/api?id=1",
		Ip:         "198.51.100.8",
		Time:       "2026-11-28 12:00:00",
	})
	if strings.Contains(evNoLoc.DefaultContent, "()") {
		t.Fatalf("default content should not append empty parentheses: %q", evNoLoc.DefaultContent)
	}

	// 2. 模板变量表含 Location
	foundLoc := false
	for _, v := range GetNotifyTemplateVars(model.MSG_TYPE_ATTACK_INFO) {
		if v.Name == "Location" {
			foundLoc = true
			break
		}
	}
	if !foundLoc {
		t.Fatal("MSG_TYPE_ATTACK_INFO template vars missing Location")
	}

	// 3. R8 修复：带归属地后缀的 RuleMessageInfo 与 manage_login_abnormal 均能被 ExcludeIps 正确过滤
	ruleEv := WafNotifySenderServiceApp.BuildNotifyEvent(innerbean.RuleMessageInfo{
		BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "命中保护规则", Server: "waf"},
		Domain:          "xxxx.com",
		RuleInfo:        "自定义规则",
		Ip:              "192.0.2.88 ([中国 华南 广东 深圳 电信])",
	})
	if ruleEv.DedupParts[model.DedupKeyIp] != "192.0.2.88" {
		t.Fatalf("rule dedup ip = %q, want 192.0.2.88", ruleEv.DedupParts[model.DedupKeyIp])
	}
	if MatchNotifyFilter(model.NotifyFilterConfig{ExcludeIps: []string{"192.0.2.0/24"}}, ruleEv) {
		t.Fatal("ExcludeIps CIDR failed for RuleMessageInfo with location suffix")
	}

	loginEv := WafNotifySenderServiceApp.BuildNotifyEvent(innerbean.UserLoginMessageInfo{
		Username: "admin",
		Ip:       "203.0.113.9 (广东深圳)",
		Abnormal: true,
	})
	if loginEv.DedupParts[model.DedupKeyIp] != "203.0.113.9" {
		t.Fatalf("login dedup ip = %q, want 203.0.113.9", loginEv.DedupParts[model.DedupKeyIp])
	}
	if MatchNotifyFilter(model.NotifyFilterConfig{ExcludeIps: []string{"203.0.113.9"}}, loginEv) {
		t.Fatal("ExcludeIps single IP failed for abnormal login event with location suffix")
	}
}
