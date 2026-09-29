//go:build crossdb

// ip_tags 增量写入的三库回归。
//
// 这一步是整批一条 upsert（冲突目标 = uni_iptags_full 的四列，累加表达式走
// dialect.UpsertExcludedRef，PG/SQLite 是 excluded.cnt、MySQL 是 VALUES(cnt)）。
// 任一引擎对不上，症状都是不报错的静默错账：要么每批新建一行、同一个 IP+标签出现多行，
// 要么 cnt 被覆盖成最后一批的值而不是累加。所以三边各跑一遍真实迁移 + 真实写入。
//
// 跑法：go test -tags crossdb ./waftask/ -run TestCollectStatsIPTagCrossEngine
// MySQL / PostgreSQL 连不上时跳过，不阻塞。
package waftask

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"testing"

	"gorm.io/gorm"
)

func TestCollectStatsIPTagCrossEngine(t *testing.T) {
	engines := map[string]func(*testing.T) (*gorm.DB, func()){
		"sqlite":   setupAnalysisSQLite,
		"mysql":    setupAnalysisMySQL,
		"postgres": setupAnalysisPostgres,
	}
	for name, setup := range engines {
		t.Run(name, func(t *testing.T) {
			db, done := setup(t)
			if db == nil {
				t.Skip("引擎不可用，跳过")
			}
			defer done()
			runIPTagUpsertAssertions(t, db)
		})
	}
}

func runIPTagUpsertAssertions(t *testing.T, db *gorm.DB) {
	t.Helper()

	prevStats, prevCore, prevTagDB := global.GWAF_LOCAL_STATS_DB, global.GWAF_LOCAL_DB, global.GDATA_IP_TAG_DB
	prevUser, prevTenant := global.GWAF_USER_CODE, global.GWAF_TENANT_ID
	global.GWAF_LOCAL_STATS_DB = db
	global.GWAF_LOCAL_DB = db // 只用于 CollectStatsFromLogs 的非空检查
	global.GDATA_IP_TAG_DB = 1
	global.GWAF_USER_CODE = "xtest_user"
	global.GWAF_TENANT_ID = "xtest_tenant"
	defer func() {
		global.GWAF_LOCAL_STATS_DB, global.GWAF_LOCAL_DB, global.GDATA_IP_TAG_DB = prevStats, prevCore, prevTagDB
		global.GWAF_USER_CODE, global.GWAF_TENANT_ID = prevUser, prevTenant
	}()

	const day = 20260924
	entry := func(ip, rule, action string) *innerbean.WebLog {
		return &innerbean.WebLog{
			HOST_CODE:     "h1",
			HOST:          "x.test.com",
			SRC_IP:        ip,
			RULE:          rule,
			ACTION:        action,
			Day:           day,
			USER_CODE:     "xtest_user",
			TenantId:      "xtest_tenant",
			UNIX_ADD_TIME: 1758672000000,
		}
	}
	batch := []*innerbean.WebLog{
		entry("1.1.1.1", "SQL注入", "阻止"),
		entry("1.1.1.1", "SQL注入", "阻止"),
		entry("1.1.1.1", "XSS", "阻止"),
		entry("2.2.2.2", "SQL注入", "阻止"),
		entry("3.3.3.3", "", "放行"), // 未命中规则：不该产生任何标签（D7）
	}

	// 两批相同数据：第二批必须落在 upsert 的累加分支上，而不是新建一行
	CollectStatsFromLogs(batch)
	CollectStatsFromLogs(batch)

	var rows []model.IPTag
	if err := db.Order("ip, ip_tag").Find(&rows).Error; err != nil {
		t.Fatalf("读 ip_tags 失败: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("三个 (ip,标签) 组合应只有 3 行，实际 %d 行：upsert 没命中 uni_iptags_full", len(rows))
	}

	want := map[string]int64{
		"1.1.1.1|SQL注入": 4, // 每批 2 次 × 2 批
		"1.1.1.1|XSS":    2,
		"2.2.2.2|SQL注入": 2,
	}
	for _, r := range rows {
		key := r.IP + "|" + r.IPTag
		exp, ok := want[key]
		if !ok {
			t.Fatalf("出现意料外的标签行 %s（未命中规则的请求不该生成标签）", key)
		}
		if r.Cnt != exp {
			t.Fatalf("%s 的 cnt 应累加成 %d，实际 %d（upsert 是覆盖而不是累加？）", key, exp, r.Cnt)
		}
		if r.USER_CODE != "xtest_user" || r.Tenant_ID != "xtest_tenant" {
			t.Fatalf("%s 的归属列不对: user=%q tenant=%q", key, r.USER_CODE, r.Tenant_ID)
		}
	}

	// 放行的那条 IP 只该出现在 stats_ip_days 里，不该有标签
	var tagCnt int64
	if err := db.Model(&model.IPTag{}).Where("ip = ?", "3.3.3.3").Count(&tagCnt).Error; err != nil {
		t.Fatalf("查放行 IP 标签失败: %v", err)
	}
	if tagCnt != 0 {
		t.Fatalf("未命中规则的 IP 不该有标签，实际 %d 行", tagCnt)
	}
	var dayCnt int64
	if err := db.Model(&model.StatsIPDay{}).Where("ip = ? and day = ?", "3.3.3.3", day).Count(&dayCnt).Error; err != nil {
		t.Fatalf("查 stats_ip_days 失败: %v", err)
	}
	if dayCnt == 0 {
		t.Fatal("放行数量应由 stats_ip_days 承担，这里一行都没有")
	}
}
