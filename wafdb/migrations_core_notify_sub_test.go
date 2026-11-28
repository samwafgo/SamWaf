package wafdb

import (
	"SamWaf/customtype"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"path/filepath"
	"testing"
	"time"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
)

func TestDedupAndUniqueNotifySubscriptionsMigration(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "notify-sub-migration.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		t.Cleanup(func() { _ = sqlDB.Close() })
	}

	if err := db.AutoMigrate(&model.NotifySubscription{}); err != nil {
		t.Fatal(err)
	}

	t1 := customtype.JsonTime(time.Date(2026, 11, 10, 10, 0, 0, 0, time.Local))
	t2 := customtype.JsonTime(time.Date(2026, 11, 12, 10, 0, 0, 0, time.Local))
	t3 := customtype.JsonTime(time.Date(2026, 11, 15, 10, 0, 0, 0, time.Local))

	seeds := []model.NotifySubscription{
		// 同租户同渠道同类型：旧记录启用且无域名模板
		{
			BaseOrm:         baseorm.BaseOrm{Id: "sub-old", Tenant_ID: "tenantA", USER_CODE: "userA", CREATE_TIME: t1, UPDATE_TIME: t1},
			ChannelId:       "ch-ding",
			MessageType:     model.MSG_TYPE_ATTACK_INFO,
			Status:          1,
			ContentTemplate: "old-tpl-no-domain",
		},
		// 中间版本
		{
			BaseOrm:         baseorm.BaseOrm{Id: "sub-mid", Tenant_ID: "tenantA", USER_CODE: "userA", CREATE_TIME: t2, UPDATE_TIME: t2},
			ChannelId:       "ch-ding",
			MessageType:     model.MSG_TYPE_ATTACK_INFO,
			Status:          1,
			ContentTemplate: "mid-tpl",
		},
		// 最新编辑条：即使已被用户关闭（status=0），按 D1 也应保留此条而非旧开启条
		{
			BaseOrm:         baseorm.BaseOrm{Id: "sub-latest", Tenant_ID: "tenantA", USER_CODE: "userA", CREATE_TIME: t2, UPDATE_TIME: t3},
			ChannelId:       "ch-ding",
			MessageType:     model.MSG_TYPE_ATTACK_INFO,
			Status:          0,
			ContentTemplate: "latest-tpl-with-domain",
		},
		// 不同租户同 channel_id/message_type 不得误删
		{
			BaseOrm:         baseorm.BaseOrm{Id: "sub-other-tenant", Tenant_ID: "tenantB", USER_CODE: "userB", CREATE_TIME: t1, UPDATE_TIME: t1},
			ChannelId:       "ch-ding",
			MessageType:     model.MSG_TYPE_ATTACK_INFO,
			Status:          1,
			ContentTemplate: "tenant-b-tpl",
		},
		// 同租户同渠道不同消息类型不得误删
		{
			BaseOrm:         baseorm.BaseOrm{Id: "sub-other-type", Tenant_ID: "tenantA", USER_CODE: "userA", CREATE_TIME: t1, UPDATE_TIME: t1},
			ChannelId:       "ch-ding",
			MessageType:     model.MSG_TYPE_RULE_TRIGGER,
			Status:          1,
			ContentTemplate: "rule-tpl",
		},
	}
	for i := range seeds {
		if err := db.Create(&seeds[i]).Error; err != nil {
			t.Fatalf("seed %s failed: %v", seeds[i].Id, err)
		}
	}

	// 幂等执行两次迁移
	for i := 0; i < 2; i++ {
		if err := dedupAndUniqueNotifySubscriptions(db); err != nil {
			t.Fatalf("migration run %d failed: %v", i+1, err)
		}
	}

	var remaining []model.NotifySubscription
	if err := db.Order("id asc").Find(&remaining).Error; err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 3 {
		t.Fatalf("remaining count = %d, want 3: %+v", len(remaining), remaining)
	}
	gotIDs := map[string]model.NotifySubscription{}
	for _, r := range remaining {
		gotIDs[r.Id] = r
	}
	kept, ok := gotIDs["sub-latest"]
	if !ok || kept.ContentTemplate != "latest-tpl-with-domain" || kept.Status != 0 {
		t.Fatalf("expected sub-latest kept with status=0, got: %+v", kept)
	}
	if _, ok := gotIDs["sub-other-tenant"]; !ok {
		t.Fatal("other tenant subscription was unexpectedly removed")
	}
	if _, ok := gotIDs["sub-other-type"]; !ok {
		t.Fatal("other message_type subscription was unexpectedly removed")
	}

	// 唯一索引必须拦截二次重复插入
	dup := model.NotifySubscription{
		BaseOrm:     baseorm.BaseOrm{Id: "sub-dup-after", Tenant_ID: "tenantA", USER_CODE: "userA", CREATE_TIME: t3, UPDATE_TIME: t3},
		ChannelId:   "ch-ding",
		MessageType: model.MSG_TYPE_ATTACK_INFO,
		Status:      1,
	}
	if err := db.Create(&dup).Error; err == nil {
		t.Fatal("expected unique index violation on duplicate (tenant_id, user_code, channel_id, message_type)")
	}

	// 回滚安全删索引
	if err := safeDropIndex(db, "notify_subscriptions", "uni_notify_sub_tenant_user_ch_type"); err != nil {
		t.Fatalf("rollback drop index failed: %v", err)
	}
	if db.Migrator().HasIndex("notify_subscriptions", "uni_notify_sub_tenant_user_ch_type") {
		t.Fatal("unique index still exists after rollback")
	}
}
