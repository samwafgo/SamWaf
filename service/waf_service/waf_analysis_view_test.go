package waf_service

import (
	"path/filepath"
	"testing"

	"SamWaf/common/uuid"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafdb/dialect"

	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const avDay = 20260920

// setupAnalysisViewDB 建一个临时 stats 库并灌入一组刻意设计过的数据：
// 一个扫目录的、一个换 UA 的、两个正常访客。
func setupAnalysisViewDB(t *testing.T) *gorm.DB {
	t.Helper()
	dialect.Register(&dialect.SQLiteDialect{})
	db, err := gorm.Open(
		sqlite.Open(filepath.Join(t.TempDir(), "stats.db")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)},
	)
	if err != nil {
		t.Skipf("打不开 sqlite（缺 CGO？），跳过: %v", err)
	}
	if err := db.AutoMigrate(&model.StatsActorPathDay{}, &model.StatsActorUaDay{}, &model.StatsPathRuleDay{}); err != nil {
		t.Fatalf("建表失败: %v", err)
	}
	old := global.GWAF_LOCAL_STATS_DB
	global.GWAF_LOCAL_STATS_DB = db
	t.Cleanup(func() {
		global.GWAF_LOCAL_STATS_DB = old
		if s, e := db.DB(); e == nil {
			s.Close()
		}
	})

	ap := func(host, actor, path string, req, deny, err4xx int64) model.StatsActorPathDay {
		return model.StatsActorPathDay{
			BaseOrm:  baseorm.BaseOrm{Id: uuid.GenUUID()},
			HostCode: host, Day: avDay, ActorKey: actor, PathNorm: path,
			ReqCnt: req, DenyCnt: deny, Err4xxCnt: err4xx,
		}
	}
	rows := []model.StatsActorPathDay{
		// 扫目录的：5 个不同路径，还跨了两个站点
		ap("h1", "ip:203.0.113.10", "/admin", 1, 0, 1),
		ap("h1", "ip:203.0.113.10", "/.env", 1, 1, 0),
		ap("h1", "ip:203.0.113.10", "/wp-login.php", 1, 0, 1),
		ap("h1", "ip:203.0.113.10", "/item/{n}", 5, 0, 5),
		ap("h2", "ip:203.0.113.10", "/backup.zip", 2, 0, 2),
		// 换 UA 的：只摸一个路径，但请求最多
		ap("h1", "ip:203.0.113.20", "/api/products", 20, 0, 0),
		// 两个正常访客
		ap("h1", "ip:198.51.100.10", "/", 6, 0, 0),
		ap("h1", "ip:198.51.100.10", "/api/products", 3, 0, 0),
		ap("h1", "ip:198.51.100.11", "/", 4, 0, 0),
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("灌数据失败: %v", err)
	}
	uas := []model.StatsActorUaDay{
		{BaseOrm: baseorm.BaseOrm{Id: uuid.GenUUID()}, HostCode: "h1", Day: avDay, ActorKey: "ip:203.0.113.20", UaHash: "ua1", Cnt: 3},
		{BaseOrm: baseorm.BaseOrm{Id: uuid.GenUUID()}, HostCode: "h1", Day: avDay, ActorKey: "ip:203.0.113.20", UaHash: "ua2", Cnt: 3},
		{BaseOrm: baseorm.BaseOrm{Id: uuid.GenUUID()}, HostCode: "h1", Day: avDay, ActorKey: "ip:203.0.113.20", UaHash: "ua3", Cnt: 3},
		{BaseOrm: baseorm.BaseOrm{Id: uuid.GenUUID()}, HostCode: "h1", Day: avDay, ActorKey: "ip:203.0.113.10", UaHash: "ua9", Cnt: 10},
		{BaseOrm: baseorm.BaseOrm{Id: uuid.GenUUID()}, HostCode: "h1", Day: avDay, ActorKey: "ip:198.51.100.10", UaHash: "ua1", Cnt: 9},
	}
	if err := db.Create(&uas).Error; err != nil {
		t.Fatalf("灌 UA 数据失败: %v", err)
	}
	rules := []model.StatsPathRuleDay{
		{BaseOrm: baseorm.BaseOrm{Id: uuid.GenUUID()}, HostCode: "h1", Day: avDay, PathNorm: "/.env", Rule: "敏感文件", Cnt: 1},
		{BaseOrm: baseorm.BaseOrm{Id: uuid.GenUUID()}, HostCode: "h1", Day: avDay, PathNorm: "/api/products", Rule: "SQL注入", Cnt: 5},
		{BaseOrm: baseorm.BaseOrm{Id: uuid.GenUUID()}, HostCode: "h1", Day: avDay, PathNorm: "/api/products", Rule: "XSS跨站注入", Cnt: 2},
	}
	if err := db.Create(&rules).Error; err != nil {
		t.Fatalf("灌规则数据失败: %v", err)
	}
	return db
}

// 行为视角的命门：distinct_path 必须是真去重，且默认按它倒序——扫目录的要排第一。
func TestAnalysisActorList(t *testing.T) {
	setupAnalysisViewDB(t)
	resp := WafAnalysisViewServiceApp.ActorListApi(request.WafAnalysisActorReq{Day: avDay})

	if len(resp.List) != 4 {
		t.Fatalf("应有 4 个来源，实际 %d", len(resp.List))
	}
	top := resp.List[0]
	if top.ActorKey != "ip:203.0.113.10" {
		t.Fatalf("默认按去重路径倒序，扫目录的该排第一，实际 %q", top.ActorKey)
	}
	if top.DistinctPath != 5 {
		t.Fatalf("它摸了 5 个不同路径，实际 %d", top.DistinctPath)
	}
	if top.ReqCnt != 10 || top.DenyCnt != 1 || top.Err4xxCnt != 9 {
		t.Fatalf("跨站点求和不对：req=%d deny=%d err4xx=%d", top.ReqCnt, top.DenyCnt, top.Err4xxCnt)
	}
	// UA 数来自另一张表，必须按 actor 正确贴回
	if top.UaCnt != 1 {
		t.Fatalf("扫目录的只有 1 种 UA，实际 %d", top.UaCnt)
	}
	for _, r := range resp.List {
		if r.ActorKey == "ip:203.0.113.20" && r.UaCnt != 3 {
			t.Fatalf("换 UA 的应有 3 种 UA，实际 %d", r.UaCnt)
		}
	}
	if resp.TotalActor != 4 {
		t.Fatalf("总来源数应为 4，实际 %d", resp.TotalActor)
	}
}

// 排序字段是拼进 SQL 的东西，只能走白名单映射。
// 传个注入串进来必须被丢弃回落默认序，而不是报错或者真去执行它。
func TestAnalysisActorSortWhitelist(t *testing.T) {
	setupAnalysisViewDB(t)
	evil := request.WafAnalysisActorReq{Day: avDay, SortBy: "req_cnt desc; drop table stats_actor_path_days --"}
	resp := WafAnalysisViewServiceApp.ActorListApi(evil)
	if len(resp.List) != 4 {
		t.Fatalf("非法排序值应被忽略并照常返回，实际 %d 行", len(resp.List))
	}
	if resp.List[0].ActorKey != "ip:203.0.113.10" {
		t.Fatalf("应回落到默认的去重路径倒序，实际首行 %q", resp.List[0].ActorKey)
	}
	// 表还在
	var n int64
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsActorPathDay{}).Count(&n)
	if n == 0 {
		t.Fatal("表没了——排序值被拼进 SQL 执行了")
	}

	// 合法值要真的生效
	byReq := WafAnalysisViewServiceApp.ActorListApi(request.WafAnalysisActorReq{Day: avDay, SortBy: "req_cnt"})
	if byReq.List[0].ActorKey != "ip:203.0.113.20" {
		t.Fatalf("按请求数倒序首位应是 20，实际 %q", byReq.List[0].ActorKey)
	}
}

// 目标视角：去重来源数 + top_rule 取最大的那条。
func TestAnalysisPathList(t *testing.T) {
	setupAnalysisViewDB(t)
	resp := WafAnalysisViewServiceApp.PathListApi(request.WafAnalysisPathReq{Day: avDay})

	var products *struct {
		Req, Actor int64
		Rule       string
	}
	for _, r := range resp.List {
		if r.PathNorm == "/api/products" {
			products = &struct {
				Req, Actor int64
				Rule       string
			}{r.ReqCnt, r.DistinctActor, r.TopRule}
		}
	}
	if products == nil {
		t.Fatal("没查到 /api/products")
	}
	if products.Req != 23 {
		t.Fatalf("/api/products 请求数应为 23，实际 %d", products.Req)
	}
	if products.Actor != 2 {
		t.Fatalf("两个不同来源打过它，实际 %d", products.Actor)
	}
	if products.Rule != "SQL注入" {
		t.Fatalf("top_rule 该取次数最多的 SQL注入，实际 %q", products.Rule)
	}
	// 7 个：/admin /.env /wp-login.php /item/{n} /backup.zip /api/products /
	if resp.TotalPath != 7 {
		t.Fatalf("路径模板数应为 7，实际 %d", resp.TotalPath)
	}
}

// 站点过滤要真的收窄：只看 h1 时，跨站的那个来源只剩 h1 那部分。
func TestAnalysisHostFilter(t *testing.T) {
	setupAnalysisViewDB(t)
	resp := WafAnalysisViewServiceApp.ActorListApi(request.WafAnalysisActorReq{Day: avDay, HostCode: "h1"})
	for _, r := range resp.List {
		if r.ActorKey == "ip:203.0.113.10" {
			if r.DistinctPath != 4 || r.ReqCnt != 8 {
				t.Fatalf("按 h1 过滤后该来源应是 4 个路径 / 8 次请求，实际 %d / %d", r.DistinctPath, r.ReqCnt)
			}
			return
		}
	}
	t.Fatal("没查到该来源")
}

// 抽屉：actor 模式要给出站点清单——加黑/加白的 host_code 必填，界面靠它选。
func TestAnalysisDetailActor(t *testing.T) {
	setupAnalysisViewDB(t)
	resp := WafAnalysisViewServiceApp.DetailApi(request.WafAnalysisDetailReq{
		Day: avDay, Kind: "actor", Key: "ip:203.0.113.10",
	})
	if len(resp.Paths) != 5 {
		t.Fatalf("该来源摸过 5 个路径，实际 %d", len(resp.Paths))
	}
	if len(resp.Hosts) != 2 {
		t.Fatalf("它跨了 2 个站点，实际 %d——加黑时就没得选了", len(resp.Hosts))
	}
	if resp.Hosts[0].HostCode != "h1" {
		t.Fatalf("站点应按请求数倒序，首位该是 h1，实际 %q", resp.Hosts[0].HostCode)
	}
	if len(resp.Uas) != 1 {
		t.Fatalf("它只有 1 种 UA，实际 %d", len(resp.Uas))
	}
	if resp.ReqCnt != 10 {
		t.Fatalf("合计请求数应为 10，实际 %d", resp.ReqCnt)
	}
}

func TestAnalysisDetailPath(t *testing.T) {
	setupAnalysisViewDB(t)
	resp := WafAnalysisViewServiceApp.DetailApi(request.WafAnalysisDetailReq{
		Day: avDay, Kind: "path", Key: "/api/products",
	})
	if len(resp.Actors) != 2 {
		t.Fatalf("两个来源打过它，实际 %d", len(resp.Actors))
	}
	if resp.Actors[0].ActorKey != "ip:203.0.113.20" {
		t.Fatalf("来源应按请求数倒序，实际首位 %q", resp.Actors[0].ActorKey)
	}
	if len(resp.Rules) != 2 || resp.Rules[0].Rule != "SQL注入" {
		t.Fatalf("规则分布应是两条、SQL注入在前，实际 %+v", resp.Rules)
	}
}

// 阈值来自系统配置，改了要跟着走；「疑似」计数按阈值现算。
func TestAnalysisThresholdCounts(t *testing.T) {
	setupAnalysisViewDB(t)
	oldScan, oldUa := global.GDATA_ANALYSIS_SCAN_PATH_THRESHOLD, global.GDATA_ANALYSIS_UA_THRESHOLD
	t.Cleanup(func() {
		global.GDATA_ANALYSIS_SCAN_PATH_THRESHOLD, global.GDATA_ANALYSIS_UA_THRESHOLD = oldScan, oldUa
	})

	global.GDATA_ANALYSIS_SCAN_PATH_THRESHOLD = 5
	global.GDATA_ANALYSIS_UA_THRESHOLD = 3
	resp := WafAnalysisViewServiceApp.ActorListApi(request.WafAnalysisActorReq{Day: avDay})
	if resp.ScanActor != 1 || resp.UaActor != 1 {
		t.Fatalf("阈值 5/3 时各应命中 1 个，实际 scan=%d ua=%d", resp.ScanActor, resp.UaActor)
	}
	if resp.ScanThreshold != 5 || resp.UaThreshold != 3 {
		t.Fatal("返回的阈值应是当前配置值，界面要拿它显示")
	}

	global.GDATA_ANALYSIS_SCAN_PATH_THRESHOLD = 99
	resp = WafAnalysisViewServiceApp.ActorListApi(request.WafAnalysisActorReq{Day: avDay})
	if resp.ScanActor != 0 {
		t.Fatalf("阈值调到 99 后不该有人命中，实际 %d", resp.ScanActor)
	}
}
