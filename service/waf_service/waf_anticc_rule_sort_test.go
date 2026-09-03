package waf_service

import (
	"path/filepath"
	"testing"

	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupCCRuleSortDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(
		sqlite.Open(filepath.Join(t.TempDir(), "ccrule_sort.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
	)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	if err := db.AutoMigrate(&model.AntiCCRule{}); err != nil {
		t.Fatalf("AutoMigrate 失败: %v", err)
	}
	old := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = db
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB = old
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

func mkRule(t *testing.T, db *gorm.DB, id, host string, priority int) {
	t.Helper()
	r := model.AntiCCRule{HostCode: host, RuleName: id, Priority: priority}
	r.BaseOrm = baseorm.BaseOrm{Id: id}
	if err := db.Create(&r).Error; err != nil {
		t.Fatalf("建规则失败: %v", err)
	}
}

func prio(t *testing.T, db *gorm.DB, id string) int {
	t.Helper()
	var r model.AntiCCRule
	if err := db.Where("id = ?", id).First(&r).Error; err != nil {
		t.Fatalf("读规则失败: %v", err)
	}
	return r.Priority
}

// 只在提交的这批规则原本占用的槽位之间重排。
// 列表是分页的，提交上来的可能只是该站点规则的一部分；按位置从 10 重编
// 会把没提交的规则挤到后面，用户没动过的顺序凭空变了。
func TestCCRuleSort_KeepsUnsubmittedRulesInPlace(t *testing.T) {
	db := setupCCRuleSortDB(t)
	mkRule(t, db, "a", "h1", 10)
	mkRule(t, db, "b", "h1", 20)
	mkRule(t, db, "c", "h1", 30) // 不在本次提交里（比如在下一页）

	if err := WafAntiCCRuleServiceApp.SortApi(request.WafAntiCCRuleSortReq{
		HostCode: "h1", Ids: []string{"b", "a"},
	}); err != nil {
		t.Fatalf("排序失败: %v", err)
	}
	if got := prio(t, db, "b"); got != 10 {
		t.Fatalf("b 应换到 10 号槽位，实际 %d", got)
	}
	if got := prio(t, db, "a"); got != 20 {
		t.Fatalf("a 应换到 20 号槽位，实际 %d", got)
	}
	if got := prio(t, db, "c"); got != 30 {
		t.Fatalf("没提交的 c 不该被动，期望 30，实际 %d", got)
	}
}

// 存量数据里同一站点的优先级可能重复（默认值都是 100）。
// 槽位不强制递增的话交换就成了空操作，界面上看就是「点了没反应」。
func TestCCRuleSort_HandlesDuplicatePriorities(t *testing.T) {
	db := setupCCRuleSortDB(t)
	mkRule(t, db, "a", "h1", 100)
	mkRule(t, db, "b", "h1", 100)

	if err := WafAntiCCRuleServiceApp.SortApi(request.WafAntiCCRuleSortReq{
		HostCode: "h1", Ids: []string{"b", "a"},
	}); err != nil {
		t.Fatalf("排序失败: %v", err)
	}
	pa, pb := prio(t, db, "a"), prio(t, db, "b")
	if pb >= pa {
		t.Fatalf("交换后 b 应排在 a 前面，实际 b=%d a=%d", pb, pa)
	}
}

// 传了不属于该站点的 id 要报错，而不是把别人的规则一起重排
func TestCCRuleSort_RejectsForeignIds(t *testing.T) {
	db := setupCCRuleSortDB(t)
	mkRule(t, db, "a", "h1", 10)
	mkRule(t, db, "x", "h2", 10)

	if err := WafAntiCCRuleServiceApp.SortApi(request.WafAntiCCRuleSortReq{
		HostCode: "h1", Ids: []string{"a", "x"},
	}); err == nil {
		t.Fatal("提交了别的站点的规则却没报错")
	}
	if got := prio(t, db, "x"); got != 10 {
		t.Fatalf("别的站点的规则不该被动，实际 %d", got)
	}
}
