package waf_service

import (
	"path/filepath"
	"testing"

	"SamWaf/common/uuid"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openOrphanTestDB 打开一个临时 sqlite 测试库（用例结束自动关闭）。
func openOrphanTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "orphan_cc.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("打开 sqlite 测试库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.Hosts{}, &model.AntiCCRule{}); err != nil {
		t.Fatalf("AutoMigrate 失败: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

// withLocalDB 把全局库临时换成测试库，用例结束还原。
func withLocalDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	old := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = db
	t.Cleanup(func() { global.GWAF_LOCAL_DB = old })
}

func countCCRules(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AntiCCRule{}).Count(&n).Error; err != nil {
		t.Fatalf("统计 CC 规则失败: %v", err)
	}
	return n
}

// 站点还在的规则要留下，站点没了的规则要删掉——这是本用例的全部约束。
func TestCleanupOrphanRulesRemovesOnlyOrphans(t *testing.T) {
	db := openOrphanTestDB(t)
	withLocalDB(t, db)

	// Id 是字符串主键，必须显式给唯一值：留空时三条记录会落到同一个主键上互相覆盖。
	db.Create(&model.Hosts{Code: "alive-host", Host: "a.example.com"})
	for i, code := range []string{"alive-host", "alive-host", "deleted-host"} {
		db.Create(&model.AntiCCRule{
			BaseOrm:  baseorm.BaseOrm{Id: uuid.GenUUID()},
			HostCode: code,
			RuleCode: "CC-" + code[:4] + string(rune('A'+i)),
		})
	}
	if got := countCCRules(t, db); got != 3 {
		t.Fatalf("前置数据不对: 期望 3 条规则，实际 %d", got)
	}

	n, err := WafAntiCCRuleServiceApp.CleanupOrphanRules()
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("应只删 1 条孤儿规则，实际删除 %d 条", n)
	}
	if got := countCCRules(t, db); got != 2 {
		t.Fatalf("清理后应剩 2 条，实际 %d", got)
	}

	// 活站点的规则必须原样保留，不能顺手删掉。
	var left []model.AntiCCRule
	db.Find(&left)
	for _, r := range left {
		if r.HostCode != "alive-host" {
			t.Fatalf("活站点规则被误删或孤儿规则残留: %s", r.HostCode)
		}
	}
}

// 幂等：清理干净的库再跑一次不应报错，也不应删掉任何东西。
func TestCleanupOrphanRulesIsIdempotent(t *testing.T) {
	db := openOrphanTestDB(t)
	withLocalDB(t, db)

	db.Create(&model.Hosts{Code: "alive-host"})
	db.Create(&model.AntiCCRule{
		BaseOrm:  baseorm.BaseOrm{Id: uuid.GenUUID()},
		HostCode: "alive-host",
		RuleCode: "CC-KEEP",
	})

	for i := 0; i < 2; i++ {
		n, err := WafAntiCCRuleServiceApp.CleanupOrphanRules()
		if err != nil {
			t.Fatalf("第 %d 次清理失败: %v", i+1, err)
		}
		if n != 0 {
			t.Fatalf("第 %d 次清理不应删除任何规则，实际删除 %d 条", i+1, n)
		}
	}
	if got := countCCRules(t, db); got != 1 {
		t.Fatalf("规则数应保持 1，实际 %d", got)
	}
}
