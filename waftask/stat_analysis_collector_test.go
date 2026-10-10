package waftask

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafdb/dialect"
	"net/url"
	"path/filepath"
	"testing"

	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestPathGateOverflow(t *testing.T) {
	g := &pathGate{seen: map[int]map[string]map[string]struct{}{}}
	const day = 20260919

	// 上限内的模板原样收下，且认过的再来还是它自己（不会因为已满被改判）
	first := g.admit("h1", day, "/login")
	for i := 1; i < pathTemplatePerSiteDay; i++ {
		g.admit("h1", day, "/p"+string(rune('a'+i%26))+string(rune(i)))
	}
	if first != "/login" {
		t.Fatalf("上限内的模板应原样返回，实际 %q", first)
	}
	if got := g.admit("h1", day, "/login"); got != "/login" {
		t.Fatalf("已认下的模板应一直原样返回，实际 %q", got)
	}

	// 满了之后的新模板进 {overflow}——这是扫目录时汇总表不被打爆的唯一屏障
	if got := g.admit("h1", day, "/never-seen-before"); got != pathOverflowTemplate {
		t.Fatalf("超上限的新模板应归进 %s，实际 %q", pathOverflowTemplate, got)
	}

	// 另一个站点自己算自己的，不受隔壁影响
	if got := g.admit("h2", day, "/never-seen-before"); got != "/never-seen-before" {
		t.Fatalf("上限是按站点算的，实际 %q", got)
	}
}

func TestPathGatePrunesOldDays(t *testing.T) {
	g := &pathGate{seen: map[int]map[string]map[string]struct{}{}}
	for _, day := range []int{20260917, 20260918, 20260919, 20260920} {
		g.admit("h1", day, "/x")
	}
	if len(g.seen) > 2 {
		t.Fatalf("跨天的桶应被清掉，只留最近两天，实际留了 %d 天", len(g.seen))
	}
	if _, ok := g.seen[20260920]; !ok {
		t.Fatal("当天的桶不该被清掉")
	}
}

func openAnalysisTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dialect.Register(&dialect.SQLiteDialect{})
	dsn := filepath.Join(t.TempDir(), "stats.db") + "?_db_key=" + url.QueryEscape("ktest")
	db, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Skipf("打不开 sqlite（缺 CGO？），跳过真实库用例: %v", err)
	}
	if err := db.AutoMigrate(&model.StatsActorPathDay{}, &model.StatsActorUaDay{}, &model.StatsPathRuleDay{}); err != nil {
		t.Skipf("建表失败，跳过真实库用例: %v", err)
	}
	// upsert 要有冲突目标才会走累加分支，否则每批都新建行、计数翻倍
	for _, sql := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS uni_stats_actor_path_days ON stats_actor_path_days (user_code, tenant_id, host_code, day, actor_key, path_norm)",
		"CREATE UNIQUE INDEX IF NOT EXISTS uni_stats_actor_ua_days ON stats_actor_ua_days (user_code, tenant_id, host_code, day, actor_key, ua_hash)",
		"CREATE UNIQUE INDEX IF NOT EXISTS uni_stats_path_rule_days ON stats_path_rule_days (user_code, tenant_id, host_code, day, path_norm, rule)",
	} {
		if err := db.Exec(sql).Error; err != nil {
			t.Fatalf("建唯一索引失败: %v", err)
		}
	}
	t.Cleanup(func() {
		if sqlDB, e := db.DB(); e == nil {
			sqlDB.Close()
		}
	})
	return db
}

// 分析层的全部价值建立在「计数器可累加、去重数由 GROUP BY 现算」上。
// 这个用例把两条都钉死：同一批键分两次进来必须累加成一行，
// 而去重 IP 数 / 去重路径数必须是真去重、不随批次翻倍。
func TestCollectAnalysisStats_AccumulateAndDistinct(t *testing.T) {
	db := openAnalysisTestDB(t)
	prev := global.GWAF_LOCAL_STATS_DB
	global.GWAF_LOCAL_STATS_DB = db
	t.Cleanup(func() { global.GWAF_LOCAL_STATS_DB = prev })
	analysisPathGate = &pathGate{seen: map[int]map[string]map[string]struct{}{}}

	const day = 20260919
	row := func(actor, path, ua, rule, action string, code int) model.LogAnalysisRow {
		return model.LogAnalysisRow{
			HostCode: "h1", Day: day, ActorKey: actor, PathNorm: path,
			UaHash: ua, Rule: rule, Action: action, StatusCode: code,
		}
	}

	// 第一批：A 打 /login 和 /admin，B 打 /login
	CollectAnalysisStats([]model.LogAnalysisRow{
		row("ip:1.1.1.1", "/login", "ua1", "", "放行", 200),
		row("ip:1.1.1.1", "/admin", "ua1", "", "放行", 404),
		row("ip:2.2.2.2", "/login", "ua2", "SQL注入", "阻止", 403),
	})
	// 第二批：同样的键再来一遍，必须累加进同几行而不是新建
	CollectAnalysisStats([]model.LogAnalysisRow{
		row("ip:1.1.1.1", "/login", "ua1", "", "放行", 200),
		row("ip:2.2.2.2", "/login", "ua2", "SQL注入", "阻止", 403),
	})

	var rows []model.StatsActorPathDay
	if err := db.Order("actor_key, path_norm").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("三个 (actor,path) 对应三行，实际 %d 行（upsert 没走累加分支？）", len(rows))
	}
	got := map[string]model.StatsActorPathDay{}
	for _, r := range rows {
		got[r.ActorKey+" "+r.PathNorm] = r
	}
	if v := got["ip:1.1.1.1 /login"]; v.ReqCnt != 2 {
		t.Fatalf("同键两批应累加成 2，实际 %d", v.ReqCnt)
	}
	if v := got["ip:1.1.1.1 /admin"]; v.Err4xxCnt != 1 || v.DenyCnt != 0 {
		t.Fatalf("后端 404 应只进 err4xx，实际 err4xx=%d deny=%d", v.Err4xxCnt, v.DenyCnt)
	}
	// WAF 拦截页也是 403，但它是「被挡」不是「扫出来的 4xx」，两者不能混
	if v := got["ip:2.2.2.2 /login"]; v.DenyCnt != 2 || v.Err4xxCnt != 0 {
		t.Fatalf("WAF 拦截应只进 deny，实际 deny=%d err4xx=%d", v.DenyCnt, v.Err4xxCnt)
	}

	// 目标视角：/login 被 2 个不同 IP 打过——这个数必须是 2，不能因为发了两批变 4
	var distinctIP int64
	if err := db.Model(&model.StatsActorPathDay{}).
		Where("host_code = ? and day = ? and path_norm = ?", "h1", day, "/login").
		Distinct("actor_key").Count(&distinctIP).Error; err != nil {
		t.Fatal(err)
	}
	if distinctIP != 2 {
		t.Fatalf("/login 的去重 IP 数应为 2，实际 %d", distinctIP)
	}

	// 行为视角：A 摸过 2 个不同路径（扫描信号就看这个数）
	var distinctPath int64
	if err := db.Model(&model.StatsActorPathDay{}).
		Where("host_code = ? and day = ? and actor_key = ?", "h1", day, "ip:1.1.1.1").
		Distinct("path_norm").Count(&distinctPath).Error; err != nil {
		t.Fatal(err)
	}
	if distinctPath != 2 {
		t.Fatalf("ip:1.1.1.1 的去重路径数应为 2，实际 %d", distinctPath)
	}

	// UA 表：两个 actor 各一种 UA，且同样累加
	var uaRows []model.StatsActorUaDay
	if err := db.Find(&uaRows).Error; err != nil {
		t.Fatal(err)
	}
	if len(uaRows) != 2 {
		t.Fatalf("两个 actor 各一种 UA 应是 2 行，实际 %d", len(uaRows))
	}

	// 规则表：只有命中规则的请求进，且累加
	var ruleRows []model.StatsPathRuleDay
	if err := db.Find(&ruleRows).Error; err != nil {
		t.Fatal(err)
	}
	if len(ruleRows) != 1 || ruleRows[0].Rule != "SQL注入" || ruleRows[0].Cnt != 2 {
		t.Fatalf("规则分布应是 SQL注入×2 一行，实际 %+v", ruleRows)
	}
}

// 没有 host_code 或没有 actor_key 的行聚合不出任何有意义的键，必须丢掉，
// 否则会攒出一堆空键行把汇总表污染成垃圾。
func TestCollectAnalysisStats_SkipsUnkeyedRows(t *testing.T) {
	db := openAnalysisTestDB(t)
	prev := global.GWAF_LOCAL_STATS_DB
	global.GWAF_LOCAL_STATS_DB = db
	t.Cleanup(func() { global.GWAF_LOCAL_STATS_DB = prev })
	analysisPathGate = &pathGate{seen: map[int]map[string]map[string]struct{}{}}

	CollectAnalysisStats([]model.LogAnalysisRow{
		{HostCode: "", Day: 20260919, ActorKey: "ip:1.1.1.1", PathNorm: "/x", Action: "放行"},
		{HostCode: "h1", Day: 20260919, ActorKey: "", PathNorm: "/x", Action: "放行"},
	})

	var cnt int64
	if err := db.Model(&model.StatsActorPathDay{}).Count(&cnt).Error; err != nil {
		t.Fatal(err)
	}
	if cnt != 0 {
		t.Fatalf("无键的行不该落库，实际落了 %d 行", cnt)
	}
}
