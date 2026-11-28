//go:build crossdb

// 通知订阅去重迁移、唯一索引与写路径防重/租户隔离的三库（SQLite / MySQL / PostgreSQL）回归。
package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"errors"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"
)

func dropNotifySubUniqueIndex(t *testing.T, db *gorm.DB) {
	t.Helper()
	const idx = "uni_notify_sub_tenant_user_ch_type"
	if !db.Migrator().HasIndex("notify_subscriptions", idx) {
		return
	}
	if dialect.Get().Name() == "mysql" {
		must(t, db.Exec(fmt.Sprintf("DROP INDEX `%s` ON `notify_subscriptions`", idx)).Error)
		return
	}
	must(t, db.Exec(fmt.Sprintf("DROP INDEX IF EXISTS %s", idx)).Error)
}

func runNotifySubscriptionDedupCases(t *testing.T, db *gorm.DB) {
	t.Run("NotifySubscriptionDedup", func(t *testing.T) {
		const (
			migID = "202611280001_dedup_and_unique_notify_subscriptions"
			idx   = "uni_notify_sub_tenant_user_ch_type"
		)

		if !db.Migrator().HasIndex("notify_subscriptions", idx) {
			t.Fatalf("新库迁移后 notify_subscriptions 应包含唯一索引 %s", idx)
		}

		// 模拟旧实例（无唯一索引且未执行该迁移），写入重复订阅与跨租户数据后重跑真实 core 迁移。
		chID := "ch_xtest_" + sfx()
		otherTenant := "other_tenant_" + sfx()
		otherUser := "other_user_" + sfx()

		db.Callback().Query().Before("gorm:query").Remove("tenant_plugin:before_query")
		dropNotifySubUniqueIndex(t, db)
		must(t, db.Exec("DELETE FROM migrations WHERE id = ?", migID).Error)

		t1 := customtype.JsonTime(time.Date(2026, 11, 10, 10, 0, 0, 0, time.Local))
		t2 := customtype.JsonTime(time.Date(2026, 11, 12, 10, 0, 0, 0, time.Local))
		t3 := customtype.JsonTime(time.Date(2026, 11, 15, 10, 0, 0, 0, time.Local))

		oldID := "sub_old_" + sfx()
		midID := "sub_mid_" + sfx()
		latestID := "sub_new_" + sfx()
		otherTenantID := "sub_ot_" + sfx()
		otherTypeID := "sub_rt_" + sfx()

		seeds := []model.NotifySubscription{
			{
				BaseOrm:         baseorm.BaseOrm{Id: oldID, Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE, CREATE_TIME: t1, UPDATE_TIME: t1},
				ChannelId:       chID,
				MessageType:     model.MSG_TYPE_ATTACK_INFO,
				Status:          1,
				ContentTemplate: "old-no-domain",
			},
			{
				BaseOrm:         baseorm.BaseOrm{Id: midID, Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE, CREATE_TIME: t2, UPDATE_TIME: t2},
				ChannelId:       chID,
				MessageType:     model.MSG_TYPE_ATTACK_INFO,
				Status:          1,
				ContentTemplate: "mid",
			},
			{
				BaseOrm:         baseorm.BaseOrm{Id: latestID, Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE, CREATE_TIME: t2, UPDATE_TIME: t3},
				ChannelId:       chID,
				MessageType:     model.MSG_TYPE_ATTACK_INFO,
				Status:          0,
				ContentTemplate: "latest-with-domain",
			},
			{
				BaseOrm:         baseorm.BaseOrm{Id: otherTenantID, Tenant_ID: otherTenant, USER_CODE: otherUser, CREATE_TIME: t1, UPDATE_TIME: t1},
				ChannelId:       chID,
				MessageType:     model.MSG_TYPE_ATTACK_INFO,
				Status:          1,
				ContentTemplate: "other-tenant-keep",
			},
			{
				BaseOrm:         baseorm.BaseOrm{Id: otherTypeID, Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE, CREATE_TIME: t1, UPDATE_TIME: t1},
				ChannelId:       chID,
				MessageType:     model.MSG_TYPE_RULE_TRIGGER,
				Status:          1,
				ContentTemplate: "rule-trigger-keep",
			},
		}
		for i := range seeds {
			must(t, db.Create(&seeds[i]).Error)
		}

		must(t, wafdb.RunCoreDBMigrations(db))
		registerTenantScope(db)

		if !db.Migrator().HasIndex("notify_subscriptions", idx) {
			t.Fatalf("升级迁移未重建唯一索引 %s", idx)
		}

		// 验证当前租户下仅保留 latestID（且 status=0 未被覆盖）与 otherTypeID
		var curSubs []model.NotifySubscription
		must(t, db.Where("channel_id = ?", chID).Find(&curSubs).Error)
		if len(curSubs) != 2 {
			t.Fatalf("当前租户去重后期望 2 条订阅，实际 %d: %+v", len(curSubs), curSubs)
		}
		byID := map[string]model.NotifySubscription{}
		for _, s := range curSubs {
			byID[s.Id] = s
		}
		kept, ok := byID[latestID]
		if !ok || kept.ContentTemplate != "latest-with-domain" || kept.Status != 0 {
			t.Fatalf("期望保留最新编辑条 %s(status=0)，实际: %+v", latestID, kept)
		}
		if _, ok := byID[otherTypeID]; !ok {
			t.Fatalf("同渠道其他消息类型订阅 %s 不应被误删", otherTypeID)
		}

		// 验证跨租户记录完好且不受当前租户 SaveConfigApi / DelApi 影响
		_ = WafNotifySubscriptionServiceApp.SaveConfigApi(otherTenantID, model.ThrottleModeRealtime, "", "", "", "cross-tenant-overwrite")
		_ = WafNotifySubscriptionServiceApp.DelApi(request.WafNotifySubscriptionDelReq{Id: otherTenantID})
		var otherCount int64
		var otherTpl string
		must(t, db.Raw("SELECT COUNT(*) FROM notify_subscriptions WHERE id = ?", otherTenantID).Scan(&otherCount).Error)
		must(t, db.Raw("SELECT content_template FROM notify_subscriptions WHERE id = ?", otherTenantID).Scan(&otherTpl).Error)
		if otherCount != 1 || otherTpl != "other-tenant-keep" {
			t.Fatalf("跨租户记录被破坏: count=%d tpl=%q", otherCount, otherTpl)
		}

		// 验证三库唯一索引冲突均被识别为 ErrNotifySubscriptionExists（AddApi 与 ModifyApi）
		err := WafNotifySubscriptionServiceApp.AddApi(request.WafNotifySubscriptionAddReq{
			ChannelId:   chID,
			MessageType: model.MSG_TYPE_ATTACK_INFO,
			Status:      1,
		})
		if !errors.Is(err, ErrNotifySubscriptionExists) {
			t.Fatalf("重复 AddApi 期望 ErrNotifySubscriptionExists，实际: %v", err)
		}
		if err := WafNotifySubscriptionServiceApp.CheckIsExistExcludeId(otherTypeID, chID, model.MSG_TYPE_ATTACK_INFO); err != nil {
			t.Fatalf("CheckIsExistExcludeId 应检出冲突，实际 err=%v", err)
		}
		err = WafNotifySubscriptionServiceApp.ModifyApi(request.WafNotifySubscriptionEditReq{
			Id:          otherTypeID,
			ChannelId:   chID,
			MessageType: model.MSG_TYPE_ATTACK_INFO,
			Status:      1,
		})
		if !errors.Is(err, ErrNotifySubscriptionExists) {
			t.Fatalf("冲突 ModifyApi 期望 ErrNotifySubscriptionExists，实际: %v", err)
		}

		// 验证带保留字 status 引号与排序的 GetSubscriptionsByMessageType 在三库均正常
		activeRule := WafNotifySubscriptionServiceApp.GetSubscriptionsByMessageType(model.MSG_TYPE_RULE_TRIGGER)
		foundRule := false
		for _, s := range activeRule {
			if s.Id == otherTypeID {
				foundRule = true
				break
			}
		}
		if !foundRule {
			t.Fatalf("GetSubscriptionsByMessageType 未返回启用中的 %s", otherTypeID)
		}

		// 清理测试记录，避免干扰同引擎后续用例
		must(t, db.Exec("DELETE FROM notify_subscriptions WHERE channel_id = ?", chID).Error)
	})
}
