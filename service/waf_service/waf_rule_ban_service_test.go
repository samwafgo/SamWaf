package waf_service

import (
	"SamWaf/cache"
	"SamWaf/cache/cachetest"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"path/filepath"
	"testing"
	"time"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestRuleBanListAndRemove(t *testing.T) {
	for name, store := range map[string]cache.CacheStore{
		"memory": cache.InitWafCache(),
		"json":   cachetest.NewJSONRoundTrip(),
	} {
		t.Run(name, func(t *testing.T) {
			const ip = "192.0.2.10"
			keyA := model.BuildRuleBanKey("host-a", ip)
			keyB := model.BuildRuleBanKey("host-b", ip)
			other := model.BuildRuleBanKey("host-a", "192.0.2.11")
			store.SetWithTTl(keyA, int64(17), 17*time.Minute)
			store.SetWithTTl(keyB, int64(23), 23*time.Minute)
			store.SetWithTTl(other, int64(31), 31*time.Minute)
			store.SetWithTTl(enums.CACHE_RULE_BAN_PRE+"invalid", int64(5), time.Minute)
			store.SetWithTTl("unrelated", int64(9), time.Minute)

			rows, err := ruleBanIPList(store, func(code string) string { return code + ".example" })
			if err != nil || len(rows) != 3 {
				t.Fatalf("list: rows=%+v err=%v", rows, err)
			}
			expected := map[string]int64{keyA: 17, keyB: 23, other: 31}
			for _, row := range rows {
				if row.BanMinutes != expected[model.BuildRuleBanKey(row.HostCode, row.IP)] {
					t.Fatalf("minutes not preserved: %+v", row)
				}
				if row.HostName != row.HostCode+".example" || row.RemainTime == "" {
					t.Fatalf("incomplete row: %+v", row)
				}
			}

			removeRuleBanIP(store, "host-a", ip)
			if store.IsKeyExist(keyA) || !store.IsKeyExist(keyB) {
				t.Fatal("site removal must only remove the selected site")
			}
			store.SetWithTTl(keyA, int64(17), 17*time.Minute)
			removeRuleBanIP(store, "", ip)
			if store.IsKeyExist(keyA) || store.IsKeyExist(keyB) || !store.IsKeyExist(other) || !store.IsKeyExist("unrelated") {
				t.Fatal("all-site removal must only remove rule bans for the selected IP")
			}
		})
	}
}

func TestRuleBanConfigSave(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "ruleban.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	oldDB, oldMode := global.GWAF_LOCAL_DB, global.GCONFIG_RULE_BAN_MODE
	global.GWAF_LOCAL_DB, global.GCONFIG_RULE_BAN_MODE = db, 0
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB, global.GCONFIG_RULE_BAN_MODE = oldDB, oldMode
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	if err := db.AutoMigrate(&model.SystemConfig{}); err != nil {
		t.Fatal(err)
	}
	req := request.WafRuleBanSetConfigReq{Mode: 1}
	if err := WafRuleBanServiceApp.SetConfigApi(req); err == nil || global.GCONFIG_RULE_BAN_MODE != 0 {
		t.Fatal("missing config must fail without changing the runtime mode")
	}
	if err := db.Create(&model.SystemConfig{Item: "rule_ban_mode", Value: "0"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := WafRuleBanServiceApp.SetConfigApi(req); err != nil {
		t.Fatal(err)
	}
	var saved model.SystemConfig
	if err := db.Where("item = ?", "rule_ban_mode").First(&saved).Error; err != nil || saved.Value != "1" || global.GCONFIG_RULE_BAN_MODE != 1 {
		t.Fatalf("save: value=%q mode=%d err=%v", saved.Value, global.GCONFIG_RULE_BAN_MODE, err)
	}
	if err := db.Callback().Update().Before("gorm:update").Register("ruleban_test_error", func(tx *gorm.DB) {
		tx.AddError(gorm.ErrInvalidTransaction)
	}); err != nil {
		t.Fatal(err)
	}
	if err := WafRuleBanServiceApp.SetConfigApi(request.WafRuleBanSetConfigReq{Mode: 0}); err == nil || global.GCONFIG_RULE_BAN_MODE != 1 {
		t.Fatal("failed update must not change the runtime mode")
	}
}
