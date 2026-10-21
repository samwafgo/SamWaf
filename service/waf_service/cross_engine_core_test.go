//go:build crossdb

// core 库 CRUD 三库回归：对每个 service 走真实 Add/Modify/Del/读回，断言不崩溃 + 数据正确。
// 由 cross_engine_test.go 的 TestCrossEngine 在三种引擎下各调一次 runCoreCases。
package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/model"
	"SamWaf/model/request"
	"testing"
	"time"

	"gorm.io/gorm"
)

// firstBy 按条件定位一条记录填入 dst（dst 需为 *model.X），失败即 Fatal。
func firstBy(t *testing.T, db *gorm.DB, dst interface{}, where string, args ...interface{}) {
	t.Helper()
	if err := db.Where(where, args...).First(dst).Error; err != nil {
		t.Fatalf("定位记录失败(%T where=%q): %v", dst, where, err)
	}
}

// sfx 生成一个短随机后缀，保证每个用例的唯一字段不与种子/其它用例冲突。
func sfx() string { return uuid.GenUUID()[:8] }

func runCoreCases(t *testing.T, db *gorm.DB) {
	// ————— 已验证的「修改类」用例（Updates(map) 列名三库兼容）—————
	runModifyMapCases(t, db)
	// ————— 新增：各 service 完整 CRUD 回路 —————
	runCoreCRUDCases(t, db)
	runCoreCRUDCasesB(t, db)
	// 名单条目启用开关（is_enable）三库回归
	runListEnableSwitchCases(t, db)
	// ————— 升级须知：生成幂等 / 状态流转 / 降级不生成 —————
	runUpgradeNoticeCases(t, db)
}

// ========================= 修改类（保留原有覆盖）=========================

func runModifyMapCases(t *testing.T, db *gorm.DB) {
	t.Run("BlockIP", func(t *testing.T) {
		id := uuid.GenUUID()
		must(t, db.Create(&model.IPBlockList{BaseOrm: newBase(id), HostCode: "h1", Ip: "1.1.1.1"}).Error)
		fatalIf(t, WafBlockIpServiceApp.ModifyApi(request.WafBlockIpEditReq{Id: id, HostCode: "h2", Ip: "1.1.1.1", Remarks: "r"}))
		assertHostCode(t, db, &model.IPBlockList{}, id)
	})
	t.Run("AllowIP", func(t *testing.T) {
		id := uuid.GenUUID()
		must(t, db.Create(&model.IPAllowList{BaseOrm: newBase(id), HostCode: "h1", Ip: "2.2.2.2"}).Error)
		fatalIf(t, WafWhiteIpServiceApp.ModifyApi(request.WafAllowIpEditReq{Id: id, HostCode: "h2", Ip: "2.2.2.2", Remarks: "r"}))
		assertHostCode(t, db, &model.IPAllowList{}, id)
	})
	t.Run("AllowUrl", func(t *testing.T) {
		id := uuid.GenUUID()
		must(t, db.Create(&model.URLAllowList{BaseOrm: newBase(id), HostCode: "h1", CompareType: "suffix", Url: "/a"}).Error)
		fatalIf(t, WafWhiteUrlServiceApp.ModifyApi(request.WafAllowUrlEditReq{Id: id, HostCode: "h2", CompareType: "prefix", Url: "/a", Remarks: "r"}))
		assertHostCode(t, db, &model.URLAllowList{}, id)
	})
	t.Run("BlockUrl", func(t *testing.T) {
		id := uuid.GenUUID()
		must(t, db.Create(&model.URLBlockList{BaseOrm: newBase(id), HostCode: "h1", CompareType: "suffix", Url: "/b"}).Error)
		fatalIf(t, WafBlockUrlServiceApp.ModifyApi(request.WafBlockUrlEditReq{Id: id, HostCode: "h2", CompareType: "prefix", Url: "/b", Remarks: "r"}))
		assertHostCode(t, db, &model.URLBlockList{}, id)
	})
	t.Run("AntiCC", func(t *testing.T) {
		id := uuid.GenUUID()
		must(t, db.Create(&model.AntiCC{BaseOrm: newBase(id), HostCode: "h1", Rate: 1, Limit: 1, LimitMode: "window"}).Error)
		fatalIf(t, WafAntiCCServiceApp.ModifyApi(request.WafAntiCCEditReq{
			Id: id, HostCode: "h2", Rate: 5, Limit: 5, LockIPMinutes: 5, LimitMode: "window",
		}))
		assertHostCode(t, db, &model.AntiCC{}, id)
	})
	t.Run("Ldp", func(t *testing.T) {
		id := uuid.GenUUID()
		must(t, db.Create(&model.LDPUrl{BaseOrm: newBase(id), HostCode: "h1", CompareType: "suffix", Url: "/c"}).Error)
		fatalIf(t, WafLdpUrlServiceApp.ModifyApi(request.WafLdpUrlEditReq{Id: id, HostCode: "h2", CompareType: "prefix", Url: "/c", Remarks: "r"}))
		assertHostCode(t, db, &model.LDPUrl{}, id)
	})
	t.Run("LoadBalance", func(t *testing.T) {
		id := uuid.GenUUID()
		must(t, db.Create(&model.LoadBalance{BaseOrm: newBase(id), HostCode: "h1", Remote_ip: "3.3.3.3", Remote_port: 80}).Error)
		fatalIf(t, WafLoadBalanceServiceApp.ModifyApi(request.WafLoadBalanceEditReq{
			Id: id, HostCode: "h2", Remote_ip: "4.4.4.4", Remote_port: 8080, Weight: 2, Remarks: "r",
		}))
		var got model.LoadBalance
		must(t, db.Where("id = ?", id).First(&got).Error)
		if got.HostCode != "h2" || got.Remote_ip != "4.4.4.4" || got.Remote_port != 8080 {
			t.Fatalf("LoadBalance 更新未落库: %+v", got)
		}
	})
	t.Run("Rule_UpdateMap", func(t *testing.T) {
		code := uuid.GenUUID()
		must(t, db.Create(&model.Rules{BaseOrm: newBase(uuid.GenUUID()), RuleCode: code, RuleName: "r1"}).Error)
		ruleMap := map[string]interface{}{
			"host_code":   "hh",
			"RuleName":    "r2",
			"user_code":   xtestUser,
			"UPDATE_TIME": customtype.JsonTime(time.Now()),
		}
		fatalIf(t, db.Model(model.Rules{}).Where("rule_code = ?", code).Updates(ruleMap).Error)
		var got model.Rules
		must(t, db.Where("rule_code = ?", code).First(&got).Error)
		if got.RuleName != "r2" {
			t.Fatalf("Rule 更新未落库: %+v", got)
		}
	})
}

func assertHostCode(t *testing.T, db *gorm.DB, dst interface{}, id string) {
	t.Helper()
	if err := db.Where("id = ?", id).First(dst).Error; err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if got := getHostCode(dst); got != "h2" {
		t.Fatalf("host_code 未更新，仍为 %q，模型 %T", got, dst)
	}
}

func getHostCode(v interface{}) string {
	switch x := v.(type) {
	case *model.IPBlockList:
		return x.HostCode
	case *model.IPAllowList:
		return x.HostCode
	case *model.URLBlockList:
		return x.HostCode
	case *model.URLAllowList:
		return x.HostCode
	case *model.AntiCC:
		return x.HostCode
	case *model.LDPUrl:
		return x.HostCode
	default:
		return ""
	}
}

// ========================= 完整 CRUD =========================

func runCoreCRUDCases(t *testing.T, db *gorm.DB) {
	t.Run("HttpAuthBase", func(t *testing.T) {
		un := "u_" + sfx()
		fatalIf(t, WafHttpAuthBaseServiceApp.AddApi(request.WafHttpAuthBaseAddReq{HostCode: "h1", UserName: un, Password: "p1"}))
		var bean model.HttpAuthBase
		firstBy(t, db, &bean, "user_name = ?", un)
		fatalIf(t, WafHttpAuthBaseServiceApp.ModifyApi(request.WafHttpAuthBaseEditReq{Id: bean.Id, HostCode: "h2", UserName: un, Password: "p2"}))
		got := WafHttpAuthBaseServiceApp.GetDetailByIdApi(bean.Id)
		if got.HostCode != "h2" || got.Password != "p2" {
			t.Fatalf("HttpAuthBase 更新未落库: %+v", got)
		}
		fatalIf(t, WafHttpAuthBaseServiceApp.DelApi(request.WafHttpAuthBaseDelReq{Id: bean.Id}))
		assertGone(t, db, &model.HttpAuthBase{}, bean.Id)
	})

	t.Run("Sensitive", func(t *testing.T) {
		content := "c_" + sfx()
		fatalIf(t, WafSensitiveServiceApp.AddApi(request.WafSensitiveAddReq{CheckDirection: "all", Action: "deny", Content: content, Remarks: "r"}))
		var bean model.Sensitive
		firstBy(t, db, &bean, "content = ?", content)
		fatalIf(t, WafSensitiveServiceApp.ModifyApi(request.WafSensitiveEditReq{Id: bean.Id, CheckDirection: "in", Action: "replace", Content: content, Remarks: "r2"}))
		got := WafSensitiveServiceApp.GetDetailByIdApi(bean.Id)
		if got.CheckDirection != "in" || got.Action != "replace" {
			t.Fatalf("Sensitive 更新未落库: %+v", got)
		}
		fatalIf(t, WafSensitiveServiceApp.DelApi(request.WafSensitiveDelReq{Id: bean.Id}))
		assertGone(t, db, &model.Sensitive{}, bean.Id)
	})

	t.Run("CaServerInfo", func(t *testing.T) {
		name := "ca_" + sfx()
		fatalIf(t, WafCaServerInfoServiceApp.AddApi(request.WafCaServerInfoAddReq{CaServerName: name, CaServerAddress: "https://x", Remarks: "r"}))
		var bean model.CaServerInfo
		firstBy(t, db, &bean, "ca_server_name = ?", name)
		fatalIf(t, WafCaServerInfoServiceApp.ModifyApi(request.WafCaServerInfoEditReq{Id: bean.Id, CaServerName: name, CaServerAddress: "https://y", Remarks: "r2"}))
		got := WafCaServerInfoServiceApp.GetDetailByIdApi(bean.Id)
		if got.CaServerAddress != "https://y" {
			t.Fatalf("CaServerInfo 更新未落库: %+v", got)
		}
		fatalIf(t, WafCaServerInfoServiceApp.DelApi(request.WafCaServerInfoDelReq{Id: bean.Id}))
		assertGone(t, db, &model.CaServerInfo{}, bean.Id)
	})

	t.Run("BlockingPage", func(t *testing.T) {
		name := "bp_" + sfx()
		fatalIf(t, WafBlockingPageServiceApp.AddApi(request.WafBlockingPageAddReq{
			BlockingPageName: name, BlockingType: "intercept", AttackType: "cc_attack", HostCode: "h1", ResponseCode: "403", ResponseContent: "blocked",
		}))
		var bean model.BlockingPage
		firstBy(t, db, &bean, "blocking_page_name = ?", name)
		fatalIf(t, WafBlockingPageServiceApp.ModifyApi(request.WafBlockingPageEditReq{
			Id: bean.Id, BlockingPageName: name, BlockingType: "intercept", AttackType: "cc_attack", HostCode: "h2", ResponseCode: "503", ResponseContent: "x",
		}))
		got := WafBlockingPageServiceApp.GetDetailByIdApi(bean.Id)
		if got.ResponseCode != "503" || got.HostCode != "h2" {
			t.Fatalf("BlockingPage 更新未落库: %+v", got)
		}
		fatalIf(t, WafBlockingPageServiceApp.DelApi(request.WafBlockingPageDelReq{Id: bean.Id}))
		assertGone(t, db, &model.BlockingPage{}, bean.Id)
	})

	t.Run("CacheRule", func(t *testing.T) {
		name := "cr_" + sfx()
		fatalIf(t, WafCacheRuleServiceApp.AddApi(request.WafCacheRuleAddReq{
			HostCode: "h1", RuleName: name, RuleType: 1, RuleContent: ".js", CacheTime: 60, Priority: 5, RequestMethod: "GET",
		}))
		var bean model.CacheRule
		firstBy(t, db, &bean, "rule_name = ?", name)
		fatalIf(t, WafCacheRuleServiceApp.ModifyApi(request.WafCacheRuleEditReq{
			Id: bean.Id, HostCode: "h2", RuleName: name, RuleType: 1, RuleContent: ".css", CacheTime: 120, Priority: 9, RequestMethod: "GET",
		}))
		got := WafCacheRuleServiceApp.GetDetailByIdApi(bean.Id)
		if got.HostCode != "h2" || got.CacheTime != 120 {
			t.Fatalf("CacheRule 更新未落库: %+v", got)
		}
		fatalIf(t, WafCacheRuleServiceApp.DelApi(request.WafCacheRuleDelReq{Id: bean.Id}))
		assertGone(t, db, &model.CacheRule{}, bean.Id)
	})

	t.Run("Tunnel", func(t *testing.T) {
		name := "tn_" + sfx()
		tn, err := WafTunnelServiceApp.AddApi(request.WafTunnelAddReq{
			Name: name, Port: "12345", Protocol: "tcp", RemoteIp: "1.2.3.4", RemotePort: 80, StartStatus: 0,
		})
		fatalIf(t, err)
		if tn == nil {
			t.Fatalf("Tunnel AddApi 返回 nil")
		}
		fatalIf(t, WafTunnelServiceApp.ModifyApi(request.WafTunnelEditReq{
			Id: tn.Id, Name: name, Port: "12346", Protocol: "tcp", RemoteIp: "1.2.3.4", RemotePort: 8080, StartStatus: 0,
		}))
		got := WafTunnelServiceApp.GetDetailByIdApi(tn.Id)
		if got.Port != "12346" || got.RemotePort != 8080 {
			t.Fatalf("Tunnel 更新未落库: %+v", got)
		}
		fatalIf(t, WafTunnelServiceApp.DelApi(request.WafTunnelDelReq{Id: tn.Id}))
		assertGone(t, db, &model.Tunnel{}, tn.Id)
	})

	t.Run("PrivateGroup", func(t *testing.T) {
		name := "pg_" + sfx()
		fatalIf(t, WafPrivateGroupServiceApp.AddApi(request.WafPrivateGroupAddReq{PrivateGroupName: name, PrivateGroupBelongCloud: "tencent"}))
		var bean model.PrivateGroup
		firstBy(t, db, &bean, "private_group_name = ?", name)
		fatalIf(t, WafPrivateGroupServiceApp.ModifyApi(request.WafPrivateGroupEditReq{Id: bean.Id, PrivateGroupName: name, PrivateGroupBelongCloud: "aliyun"}))
		got := WafPrivateGroupServiceApp.GetDetailByIdApi(bean.Id)
		if got.PrivateGroupBelongCloud != "aliyun" {
			t.Fatalf("PrivateGroup 更新未落库: %+v", got)
		}
		fatalIf(t, WafPrivateGroupServiceApp.DelApi(request.WafPrivateGroupDelReq{Id: bean.Id}))
		assertGone(t, db, &model.PrivateGroup{}, bean.Id)
	})

	t.Run("Otp", func(t *testing.T) {
		un := "otp_" + sfx()
		fatalIf(t, WafOtpServiceApp.AddApi(request.WafOtpAddReq{UserName: un, Url: "otpauth://x", Secret: "S123", Issuer: "SamWaf", Remarks: "r"}))
		var bean model.Otp
		firstBy(t, db, &bean, "user_name = ?", un)
		fatalIf(t, WafOtpServiceApp.ModifyApi(request.WafOtpEditReq{Id: bean.Id, UserName: un, Url: "otpauth://y", Secret: "S456", Issuer: "SamWaf", Remarks: "r2"}))
		got := WafOtpServiceApp.GetDetailByIdApi(bean.Id)
		if got.Secret != "S456" {
			t.Fatalf("Otp 更新未落库: %+v", got)
		}
		fatalIf(t, WafOtpServiceApp.DelApi(request.WafOtpDelReq{Id: bean.Id}))
		assertGone(t, db, &model.Otp{}, bean.Id)
	})

	t.Run("SystemConfig", func(t *testing.T) {
		item := "cfg_" + sfx()
		fatalIf(t, WafSystemConfigServiceApp.AddApi(request.WafSystemConfigAddReq{ItemClass: "test", Item: item, Value: "v1", ItemType: "string"}))
		var bean model.SystemConfig
		firstBy(t, db, &bean, "item = ?", item)
		fatalIf(t, WafSystemConfigServiceApp.ModifyApi(request.WafSystemConfigEditReq{Id: bean.Id, ItemClass: "test", Item: item, Value: "v2", ItemType: "string"}))
		got := WafSystemConfigServiceApp.GetDetailByIdApi(bean.Id)
		if got.Value != "v2" {
			t.Fatalf("SystemConfig 更新未落库: %+v", got)
		}
		fatalIf(t, WafSystemConfigServiceApp.DelApi(request.WafSystemConfigDelReq{Id: bean.Id}))
		assertGone(t, db, &model.SystemConfig{}, bean.Id)
	})

	t.Run("NotifyChannel", func(t *testing.T) {
		name := "nc_" + sfx()
		fatalIf(t, WafNotifyChannelServiceApp.AddApi(request.WafNotifyChannelAddReq{Name: name, Type: "dingtalk", WebhookURL: "http://x", Status: 1}))
		var bean model.NotifyChannel
		firstBy(t, db, &bean, "name = ?", name)
		fatalIf(t, WafNotifyChannelServiceApp.ModifyApi(request.WafNotifyChannelEditReq{Id: bean.Id, Name: name, Type: "feishu", WebhookURL: "http://y", Status: 0}))
		got := WafNotifyChannelServiceApp.GetDetailApi(request.WafNotifyChannelDetailReq{Id: bean.Id})
		if got.Type != "feishu" || got.WebhookURL != "http://y" {
			t.Fatalf("NotifyChannel 更新未落库: %+v", got)
		}
		fatalIf(t, WafNotifyChannelServiceApp.DelApi(request.WafNotifyChannelDelReq{Id: bean.Id}))
		assertGone(t, db, &model.NotifyChannel{}, bean.Id)
	})

	t.Run("NotifySubscription", func(t *testing.T) {
		ch := "chan_" + sfx()
		fatalIf(t, WafNotifySubscriptionServiceApp.AddApi(request.WafNotifySubscriptionAddReq{ChannelId: ch, MessageType: "attack", Recipients: "a@b.com", Status: 1}))
		var bean model.NotifySubscription
		firstBy(t, db, &bean, "channel_id = ? and message_type = ?", ch, "attack")
		fatalIf(t, WafNotifySubscriptionServiceApp.ModifyApi(request.WafNotifySubscriptionEditReq{Id: bean.Id, ChannelId: ch, MessageType: "attack", Recipients: "c@d.com", Status: 0}))
		got := WafNotifySubscriptionServiceApp.GetDetailApi(request.WafNotifySubscriptionDetailReq{Id: bean.Id})
		if got.Recipients != "c@d.com" {
			t.Fatalf("NotifySubscription 更新未落库: %+v", got)
		}
		fatalIf(t, WafNotifySubscriptionServiceApp.DelApi(request.WafNotifySubscriptionDelReq{Id: bean.Id}))
		assertGone(t, db, &model.NotifySubscription{}, bean.Id)
	})

	t.Run("Task", func(t *testing.T) {
		method := "m_" + sfx()
		fatalIf(t, WafTaskServiceApp.AddApi(request.WafTaskAddReq{TaskName: "n_" + sfx(), TaskUnit: "day", TaskValue: 1, TaskMethod: method}))
		var bean model.Task
		firstBy(t, db, &bean, "task_method = ?", method)
		fatalIf(t, WafTaskServiceApp.ModifyApi(request.WafTaskEditReq{Id: bean.Id, TaskName: "n2_" + sfx(), TaskUnit: "hour", TaskValue: 2, TaskMethod: method}))
		got := WafTaskServiceApp.GetDetailByIdApi(bean.Id)
		if got.TaskUnit != "hour" || got.TaskValue != 2 {
			t.Fatalf("Task 更新未落库: %+v", got)
		}
		fatalIf(t, WafTaskServiceApp.DelApi(request.WafTaskDelReq{Id: bean.Id}))
		assertGone(t, db, &model.Task{}, bean.Id)
	})

	t.Run("BatchTask", func(t *testing.T) {
		name := "bt_" + sfx()
		fatalIf(t, WafBatchServiceApp.AddApi(request.BatchTaskAddReq{
			BatchTaskName: name, BatchType: "ipdeny", BatchSourceType: "local", BatchTriggerType: "manual", BatchSource: "/tmp/x", BatchExecuteMethod: "append",
		}))
		var bean model.BatchTask
		firstBy(t, db, &bean, "batch_task_name = ?", name)
		fatalIf(t, WafBatchServiceApp.ModifyApi(request.BatchTaskEditReq{
			Id: bean.Id, BatchTaskName: name, BatchType: "ipdeny", BatchSourceType: "local", BatchTriggerType: "manual", BatchSource: "/tmp/y", BatchExecuteMethod: "append",
		}))
		got := WafBatchServiceApp.GetDetailByIdApi(bean.Id)
		if got.BatchSource != "/tmp/y" {
			t.Fatalf("BatchTask 更新未落库: %+v", got)
		}
		fatalIf(t, WafBatchServiceApp.DelApi(request.BatchTaskDeleteReq{Id: bean.Id}))
		assertGone(t, db, &model.BatchTask{}, bean.Id)
	})

	t.Run("TamperRule", func(t *testing.T) {
		url := "/t_" + sfx()
		fatalIf(t, WafTamperRuleServiceApp.AddApi(request.WafTamperRuleAddReq{HostCode: "h1", Url: url, RuleName: "n", IsEnable: 1, IgnoreQuery: 1, Remarks: "r"}))
		var bean model.TamperRule
		firstBy(t, db, &bean, "url = ?", url)
		fatalIf(t, WafTamperRuleServiceApp.ModifyApi(request.WafTamperRuleEditReq{Id: bean.Id, HostCode: "h2", Url: url, RuleName: "n2", IsEnable: 0, IgnoreQuery: 0, Remarks: "r2"}))
		got := WafTamperRuleServiceApp.GetDetailByIdApi(bean.Id)
		if got.HostCode != "h2" || got.RuleName != "n2" {
			t.Fatalf("TamperRule 更新未落库: %+v", got)
		}
		fatalIf(t, WafTamperRuleServiceApp.DelApi(request.WafTamperRuleDelReq{Id: bean.Id}))
		assertGone(t, db, &model.TamperRule{}, bean.Id)
	})

	t.Run("ShareDb", func(t *testing.T) {
		fn := "sd_" + sfx()
		sd := model.ShareDb{
			BaseOrm:     newBase(uuid.GenUUID()),
			DbLogicType: "log", FileName: fn, Cnt: 1,
			StartTime: customtype.JsonTime(time.Now()), EndTime: customtype.JsonTime(time.Now()),
		}
		// ShareDb.AddApi 按值传给 Create（ShareDb 无 default 标签，故安全，同时验证该按值路径）
		fatalIf(t, WafShareDbServiceApp.AddApi(sd))
		var bean model.ShareDb
		firstBy(t, db, &bean, "file_name = ?", fn)
		fatalIf(t, WafShareDbServiceApp.DeleteById(bean.Id))
		assertGone(t, db, &model.ShareDb{}, bean.Id)
	})

	t.Run("DelayMsg", func(t *testing.T) {
		title := "dm_" + sfx()
		fatalIf(t, WafDelayMsgServiceApp.Add("op", title, "content"))
		var bean model.DelayMsg
		firstBy(t, db, &bean, "delay_tile = ?", title)
		fatalIf(t, WafDelayMsgServiceApp.DelApi(bean.Id))
		assertGone(t, db, &model.DelayMsg{}, bean.Id)
	})
}

// ========================= 名单条目启用开关（is_enable） =========================

// runListEnableSwitchCases 四类名单 is_enable 三库一致性：
//   - service 新增未传开关字段 → 启用（产品默认）
//   - service 新增显式 0 → 停用（弹窗关着开关新增；防 default 标签把 0 吞成 1 的回归）
//   - toggle 0→读回 0→toggle 1→读回 1
//   - 裸结构体 Create 不带该字段 → 0（字段无 default 标签的语义锚；
//     若有人往模型上加回 default 标签，此用例会先红）
func runListEnableSwitchCases(t *testing.T, db *gorm.DB) {
	type iostub struct {
		addNil   func() error
		addZero  func() error
		addOne   func() error
		toggle   func(id string, v int) error
		findByHC func(hostCode string) (int, error)
	}
	zero, one := 0, 1
	mk := []struct {
		name string
		kit  func() iostub
	}{
		{"LSV_AllowIP", func() iostub {
			return iostub{
				addNil: func() error {
					return WafWhiteIpServiceApp.AddApi(request.WafAllowIpAddReq{HostCode: "hc_nil", Ip: "10.10.0.1", Remarks: "x"})
				},
				addZero: func() error {
					return WafWhiteIpServiceApp.AddApi(request.WafAllowIpAddReq{HostCode: "hc_zero", Ip: "10.10.0.2", Remarks: "x", IsEnable: &zero})
				},
				addOne: func() error {
					return WafWhiteIpServiceApp.AddApi(request.WafAllowIpAddReq{HostCode: "hc_one", Ip: "10.10.0.3", Remarks: "x", IsEnable: &one})
				},
				toggle: func(id string, v int) error {
					val := v
					_, err := WafWhiteIpServiceApp.ToggleApi(request.WafAllowIpToggleReq{Id: id, IsEnable: &val})
					return err
				},
				findByHC: func(hostCode string) (int, error) {
					var b model.IPAllowList
					if err := db.Where("host_code = ?", hostCode).First(&b).Error; err != nil {
						return -1, err
					}
					return b.IsEnable, nil
				},
			}
		}},
		{"LSV_BlockIP", func() iostub {
			return iostub{
				addNil: func() error {
					return WafBlockIpServiceApp.AddApi(request.WafBlockIpAddReq{HostCode: "hc_nil", Ip: "10.10.1.1", Remarks: "x"})
				},
				addZero: func() error {
					return WafBlockIpServiceApp.AddApi(request.WafBlockIpAddReq{HostCode: "hc_zero", Ip: "10.10.1.2", Remarks: "x", IsEnable: &zero})
				},
				addOne: func() error {
					return WafBlockIpServiceApp.AddApi(request.WafBlockIpAddReq{HostCode: "hc_one", Ip: "10.10.1.3", Remarks: "x", IsEnable: &one})
				},
				toggle: func(id string, v int) error {
					val := v
					_, err := WafBlockIpServiceApp.ToggleApi(request.WafBlockIpToggleReq{Id: id, IsEnable: &val})
					return err
				},
				findByHC: func(hostCode string) (int, error) {
					var b model.IPBlockList
					if err := db.Where("host_code = ?", hostCode).First(&b).Error; err != nil {
						return -1, err
					}
					return b.IsEnable, nil
				},
			}
		}},
		{"LSV_AllowURL", func() iostub {
			return iostub{
				addNil: func() error {
					return WafWhiteUrlServiceApp.AddApi(request.WafAllowUrlAddReq{HostCode: "hc_nil", CompareType: "等于", Url: "/lsv-nil", Remarks: "x"})
				},
				addZero: func() error {
					return WafWhiteUrlServiceApp.AddApi(request.WafAllowUrlAddReq{HostCode: "hc_zero", CompareType: "等于", Url: "/lsv-zero", Remarks: "x", IsEnable: &zero})
				},
				addOne: func() error {
					return WafWhiteUrlServiceApp.AddApi(request.WafAllowUrlAddReq{HostCode: "hc_one", CompareType: "等于", Url: "/lsv-one", Remarks: "x", IsEnable: &one})
				},
				toggle: func(id string, v int) error {
					val := v
					_, err := WafWhiteUrlServiceApp.ToggleApi(request.WafAllowUrlToggleReq{Id: id, IsEnable: &val})
					return err
				},
				findByHC: func(hostCode string) (int, error) {
					var b model.URLAllowList
					if err := db.Where("host_code = ?", hostCode).First(&b).Error; err != nil {
						return -1, err
					}
					return b.IsEnable, nil
				},
			}
		}},
		{"LSV_BlockURL", func() iostub {
			return iostub{
				addNil: func() error {
					return WafBlockUrlServiceApp.AddApi(request.WafBlockUrlAddReq{HostCode: "hc_nil", CompareType: "等于", Url: "/lsvb-nil", Remarks: "x"})
				},
				addZero: func() error {
					return WafBlockUrlServiceApp.AddApi(request.WafBlockUrlAddReq{HostCode: "hc_zero", CompareType: "等于", Url: "/lsvb-zero", Remarks: "x", IsEnable: &zero})
				},
				addOne: func() error {
					return WafBlockUrlServiceApp.AddApi(request.WafBlockUrlAddReq{HostCode: "hc_one", CompareType: "等于", Url: "/lsvb-one", Remarks: "x", IsEnable: &one})
				},
				toggle: func(id string, v int) error {
					val := v
					_, err := WafBlockUrlServiceApp.ToggleApi(request.WafBlockUrlToggleReq{Id: id, IsEnable: &val})
					return err
				},
				findByHC: func(hostCode string) (int, error) {
					var b model.URLBlockList
					if err := db.Where("host_code = ?", hostCode).First(&b).Error; err != nil {
						return -1, err
					}
					return b.IsEnable, nil
				},
			}
		}},
	}
	for _, it := range mk {
		it := it
		t.Run(it.name, func(t *testing.T) {
			k := it.kit()
			fatalIf(t, k.addNil())
			if v, err := k.findByHC("hc_nil"); err != nil || v != 1 {
				t.Fatalf("新增未传开关字段应为1(启用)，实际 %d err=%v", v, err)
			}
			fatalIf(t, k.addZero())
			if v, err := k.findByHC("hc_zero"); err != nil || v != 0 {
				t.Fatalf("新增显式0应为0(停用)，实际 %d err=%v（default 标签吞 0？）", v, err)
			}
			fatalIf(t, k.addOne())
			if v, err := k.findByHC("hc_one"); err != nil || v != 1 {
				t.Fatalf("新增显式1应为1，实际 %d err=%v", v, err)
			}
			// toggle 往返：0 落库、1 落库
			var b model.IPAllowList
			_ = b
			var id string
			switch it.name {
			case "LSV_AllowIP":
				var r model.IPAllowList
				firstBy(t, db, &r, "host_code = ?", "hc_zero")
				id = r.Id
			case "LSV_BlockIP":
				var r model.IPBlockList
				firstBy(t, db, &r, "host_code = ?", "hc_zero")
				id = r.Id
			case "LSV_AllowURL":
				var r model.URLAllowList
				firstBy(t, db, &r, "host_code = ?", "hc_zero")
				id = r.Id
			case "LSV_BlockURL":
				var r model.URLBlockList
				firstBy(t, db, &r, "host_code = ?", "hc_zero")
				id = r.Id
			}
			fatalIf(t, k.toggle(id, 0))
			if v, err := k.findByHC("hc_zero"); err != nil || v != 0 {
				t.Fatalf("toggle 0 应落库 0，实际 %d err=%v", v, err)
			}
			fatalIf(t, k.toggle(id, 1))
			if v, err := k.findByHC("hc_zero"); err != nil || v != 1 {
				t.Fatalf("toggle 1 应落库 1，实际 %d err=%v", v, err)
			}
		})
	}

	// 语义锚：不带 default 标签的字段，裸结构体 Create 零值落库 0
	// （批量导入等绕过 service 的插入路径依赖显式写 1；此用例防止有人加回 default 标签）
	t.Run("BareCreateNoDefault", func(t *testing.T) {
		hc := "hc_bare_" + sfx()
		fatalIf(t, db.Create(&model.IPAllowList{BaseOrm: newBase(uuid.GenUUID()), HostCode: hc, Ip: "10.10.2.1"}).Error)
		var b model.IPAllowList
		firstBy(t, db, &b, "host_code = ?", hc)
		if b.IsEnable != 0 {
			t.Fatalf("裸 Create 零值应落库 0（无 default 标签语义），实际 %d", b.IsEnable)
		}
	})
}
