//go:build crossdb

// 阶段4：有副作用 service 的「DB-only 安全路径」三库回归。
// 只测能纯 DB 跑通的方法，网络/文件/缓存/命令那半边不触发：
//   - Account：AddApi/ModifyApi/DelApi（AddApi 只哈希密码+Create，不写文件；写初始密码文件仅在 InitDefaultAccount）
//   - AILabel：MarkApi/UnmarkApi（log 库；对已存在的 WebLog 打标）
//   - Analysis：只读聚合（log+stats 双库），仅验证方言 SQL 可执行不崩
//
// 跳过：App（文件安装 IO）、Host（复杂 req + GWAF_CHAN_MSG）、TokenInfo（内存缓存刷新）。
package waf_service

import (
	"SamWaf/enums"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/request"
	"testing"
	"time"
)

func runSideCases(t *testing.T, x *xdb) {
	t.Run("Account", func(t *testing.T) {
		pw := "Aa1!Aa1!Aa1!Xy9#" // 尽量满足默认复杂度策略（大小写+数字+特殊+长度）
		acc1 := "acc1_" + sfx()
		acc2 := "acc2_" + sfx()
		if err := WafAccountServiceApp.AddApi(request.WafAccountAddReq{LoginAccount: acc1, LoginPassword: pw, Role: enums.ROLE_SUPER_ADMIN, Status: 1}); err != nil {
			t.Fatalf("Account AddApi(acc1) 失败: %v", err)
		}
		// 第二个账号，绕开 DelApi「只剩一个账号不能删」的保护
		fatalIf(t, WafAccountServiceApp.AddApi(request.WafAccountAddReq{LoginAccount: acc2, LoginPassword: pw, Role: enums.ROLE_AUDIT_ADMIN, Status: 1}))

		var bean model.Account
		firstBy(t, x.core, &bean, "login_account = ?", acc1)
		// 改状态 1→0（超管操作）
		fatalIf(t, WafAccountServiceApp.ModifyApi(request.WafAccountEditReq{
			Id: bean.Id, LoginAccount: acc1, Role: enums.ROLE_SUPER_ADMIN, Status: 0, Remarks: "r2",
		}, enums.ROLE_SUPER_ADMIN))
		got := WafAccountServiceApp.GetDetailByIdApi(bean.Id)
		if got.Status != 0 || got.Remarks != "r2" {
			t.Fatalf("Account 更新未落库: %+v", got)
		}
		fatalIf(t, WafAccountServiceApp.DelApi(request.WafAccountDelReq{Id: bean.Id}))
		assertGone(t, x.core, &model.Account{}, bean.Id)
	})

	t.Run("AILabel", func(t *testing.T) {
		uid := "airq_" + sfx()
		// 先在 log 库种一条 WebLog（MarkApi 会读它做快照）
		must(t, x.logdb.Create(&innerbean.WebLog{
			REQ_UUID: uid, HOST_CODE: "h1", URL: "/x", METHOD: "GET", SRC_IP: "1.2.3.4",
			ACTION: "deny", RULE: "r", STATUS_CODE: 403, USER_CODE: xtestUser, TenantId: xtestTenant,
			UNIX_ADD_TIME: time.Now().Unix(), CREATE_TIME: time.Now().Format("2006-01-02 15:04:05"),
		}).Error)
		// 打标 normal（避免 attack 触发自动分类的 wafai 依赖）
		fatalIf(t, WafAILabelServiceApp.MarkApi(request.WafAILabelMarkReq{ReqUuid: uid, HostCode: "h1", Mark: "normal"}))
		// WafLogLabelMark 实际落在 core 库（MarkApi 用 GWAF_LOCAL_DB），仅 WebLog 快照读 log 库
		var mark model.WafLogLabelMark
		firstBy(t, x.core, &mark, "req_uuid = ?", uid)
		if mark.Mark != "normal" {
			t.Fatalf("AILabel 标记未落库: %+v", mark)
		}
		fatalIf(t, WafAILabelServiceApp.UnmarkApi(uid))
		if n := countBy(t, x.core, &model.WafLogLabelMark{}, "req_uuid = ?", uid); n != 0 {
			t.Fatalf("AILabel 取消标记后仍存在 %d 条", n)
		}
	})

	t.Run("Analysis", func(t *testing.T) {
		today := time.Now().Format("20060102")
		// 只读聚合（log+stats），空数据返回空切片即可，重点是方言 SQL 在三库能执行不崩
		_ = WafAnalysisServiceApp.StatAnalysisDayCountryRangeApi(request.WafStatsAnalysisDayRangeCountryReq{StartDay: today, EndDay: today})
		_ = WafAnalysisServiceApp.AnalysisSpiderApi(request.WafAnalysisSpiderReq{StartDay: today, EndDay: today})
	})
}
