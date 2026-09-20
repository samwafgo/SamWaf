package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"strings"
	"time"

	"gorm.io/gorm"
)

// 来源与路径分析（M5 / G3）的读侧。
//
// 数据来自 stats_actor_path_days 的两个 GROUP BY：按 actor_key 出「谁在打」，
// 按 path_norm 出「打哪里」。去重数是查询时 COUNT(DISTINCT) 现算的——
// 它没法跨批次累加，所以库里不存这两列（见计划 §5.7 第 1 条）。
//
// 三条硬约束：
//  1. 排序字段只走下面的白名单映射，前端传什么都不拼进 SQL；
//  2. 每条查询都必须带 day，索引是 (host_code, day, …)，不带 day 会全表扫；
//  3. 走本服务的专用只读接口，不要引导用户去数据查询页——那边的敏感列子串
//     "key" 会把 actor_key 静默隐掉，页面上主维度会是空的。
type WafAnalysisViewService struct{}

var WafAnalysisViewServiceApp = new(WafAnalysisViewService)

const (
	analysisDefaultLimit = 20
	analysisMaxLimit     = 200
	analysisDetailLimit  = 50
)

// 排序白名单：前端传 key，服务端换成写死的 SQL 片段。
var analysisActorSort = map[string]string{
	"distinct_path": "distinct_path desc",
	"req_cnt":       "req_cnt desc",
	"deny_cnt":      "deny_cnt desc",
	"err4xx_cnt":    "err4xx_cnt desc",
}
var analysisPathSort = map[string]string{
	"req_cnt":        "req_cnt desc",
	"deny_cnt":       "deny_cnt desc",
	"err4xx_cnt":     "err4xx_cnt desc",
	"distinct_actor": "distinct_actor desc",
}

func analysisOrder(m map[string]string, key, fallback string) string {
	if v, ok := m[key]; ok {
		return v
	}
	return m[fallback]
}

func analysisDay(day int) int {
	if day > 0 {
		return day
	}
	d := 0
	for _, c := range time.Now().Format("20060102") {
		d = d*10 + int(c-'0')
	}
	return d
}

func analysisLimit(n int, def int) int {
	if n <= 0 {
		return def
	}
	if n > analysisMaxLimit {
		return analysisMaxLimit
	}
	return n
}

// scoped 统一加上 day 与可选的站点过滤。day 是索引首要过滤列，任何查询都不能少。
func (receiver *WafAnalysisViewService) scoped(tx *gorm.DB, day int, hostCode string) *gorm.DB {
	tx = tx.Where("day = ?", day)
	if strings.TrimSpace(hostCode) != "" {
		tx = tx.Where("host_code = ?", hostCode)
	}
	return tx
}

// ActorListApi 行为视角：谁在打。
func (receiver *WafAnalysisViewService) ActorListApi(req request.WafAnalysisActorReq) response2.WafAnalysisActorResp {
	day := analysisDay(req.Day)
	limit := analysisLimit(req.Limit, analysisDefaultLimit)
	resp := response2.WafAnalysisActorResp{
		Day:           day,
		List:          []response2.WafAnalysisActorRow{},
		ScanThreshold: global.GDATA_ANALYSIS_SCAN_PATH_THRESHOLD,
		UaThreshold:   global.GDATA_ANALYSIS_UA_THRESHOLD,
	}
	statsDB := global.GWAF_LOCAL_STATS_DB
	if statsDB == nil {
		return resp
	}

	receiver.scoped(statsDB.Model(&model.StatsActorPathDay{}), day, req.HostCode).
		Select("count(distinct actor_key)").Scan(&resp.TotalActor)

	receiver.scoped(statsDB.Model(&model.StatsActorPathDay{}), day, req.HostCode).
		Select("actor_key, sum(req_cnt) as req_cnt, sum(deny_cnt) as deny_cnt, " +
			"sum(err4xx_cnt) as err4xx_cnt, count(distinct path_norm) as distinct_path").
		Group("actor_key").
		Order(analysisOrder(analysisActorSort, req.SortBy, "distinct_path")).
		Limit(limit).Scan(&resp.List)

	receiver.fillUaCnt(statsDB, day, req.HostCode, resp.List)

	// 两个「疑似」计数：达到阈值的来源有几个。子查询必须带别名，PostgreSQL 不接受匿名派生表。
	scanSub := receiver.scoped(statsDB.Model(&model.StatsActorPathDay{}), day, req.HostCode).
		Select("actor_key").Group("actor_key").
		Having("count(distinct path_norm) >= ?", global.GDATA_ANALYSIS_SCAN_PATH_THRESHOLD)
	statsDB.Table("(?) as t", scanSub).Select("count(*)").Scan(&resp.ScanActor)

	uaSub := receiver.scoped(statsDB.Model(&model.StatsActorUaDay{}), day, req.HostCode).
		Select("actor_key").Group("actor_key").
		Having("count(*) >= ?", global.GDATA_ANALYSIS_UA_THRESHOLD)
	statsDB.Table("(?) as t", uaSub).Select("count(*)").Scan(&resp.UaActor)

	return resp
}

// fillUaCnt UA 种类在另一张表，单独查一次按 actor_key 贴回去。
// 不做 join：两张表各有各的索引，join 的执行计划在三种引擎上不好保证，
// 而这里最多只有 limit 行，一次 IN 查询足够。
func (receiver *WafAnalysisViewService) fillUaCnt(statsDB *gorm.DB, day int, hostCode string, rows []response2.WafAnalysisActorRow) {
	if len(rows) == 0 {
		return
	}
	keys := make([]string, 0, len(rows))
	for _, r := range rows {
		keys = append(keys, r.ActorKey)
	}
	var uaRows []struct {
		ActorKey string
		Cnt      int64
	}
	receiver.scoped(statsDB.Model(&model.StatsActorUaDay{}), day, hostCode).
		Where("actor_key in ?", keys).
		Select("actor_key, count(*) as cnt").Group("actor_key").Scan(&uaRows)

	m := make(map[string]int64, len(uaRows))
	for _, u := range uaRows {
		m[u.ActorKey] = u.Cnt
	}
	for i := range rows {
		rows[i].UaCnt = m[rows[i].ActorKey]
	}
}

// PathListApi 目标视角：打哪里。
func (receiver *WafAnalysisViewService) PathListApi(req request.WafAnalysisPathReq) response2.WafAnalysisPathResp {
	day := analysisDay(req.Day)
	limit := analysisLimit(req.Limit, analysisDefaultLimit)
	resp := response2.WafAnalysisPathResp{Day: day, List: []response2.WafAnalysisPathRow{}}
	statsDB := global.GWAF_LOCAL_STATS_DB
	if statsDB == nil {
		return resp
	}

	receiver.scoped(statsDB.Model(&model.StatsActorPathDay{}), day, req.HostCode).
		Select("count(distinct path_norm)").Scan(&resp.TotalPath)

	receiver.scoped(statsDB.Model(&model.StatsActorPathDay{}), day, req.HostCode).
		Select("path_norm, sum(req_cnt) as req_cnt, sum(deny_cnt) as deny_cnt, " +
			"sum(err4xx_cnt) as err4xx_cnt, count(distinct actor_key) as distinct_actor").
		Group("path_norm").
		Order(analysisOrder(analysisPathSort, req.SortBy, "req_cnt")).
		Limit(limit).Scan(&resp.List)

	receiver.fillTopRule(statsDB, day, req.HostCode, resp.List)
	return resp
}

// fillTopRule 规则分布在另一张表，取回本页这些路径的所有规则行，在内存里挑各自最大的那条。
// 存的是整个分布而不是一个 top_rule，读侧因此既能取 top 也能看构成。
func (receiver *WafAnalysisViewService) fillTopRule(statsDB *gorm.DB, day int, hostCode string, rows []response2.WafAnalysisPathRow) {
	if len(rows) == 0 {
		return
	}
	paths := make([]string, 0, len(rows))
	for _, r := range rows {
		paths = append(paths, r.PathNorm)
	}
	var ruleRows []struct {
		PathNorm string
		Rule     string
		Cnt      int64
	}
	receiver.scoped(statsDB.Model(&model.StatsPathRuleDay{}), day, hostCode).
		Where("path_norm in ?", paths).
		Select("path_norm, rule, sum(cnt) as cnt").Group("path_norm, rule").Scan(&ruleRows)

	type best struct {
		rule string
		cnt  int64
	}
	m := make(map[string]best, len(ruleRows))
	for _, r := range ruleRows {
		if b, ok := m[r.PathNorm]; !ok || r.Cnt > b.cnt {
			m[r.PathNorm] = best{rule: r.Rule, cnt: r.Cnt}
		}
	}
	for i := range rows {
		if b, ok := m[rows[i].PathNorm]; ok {
			rows[i].TopRule = b.rule
		}
	}
}

// DetailApi 抽屉下钻。Kind=actor 看这个来源摸过什么、用过什么 UA、打过哪些站点；
// Kind=path 看这个路径被谁打、命中过哪些规则。
func (receiver *WafAnalysisViewService) DetailApi(req request.WafAnalysisDetailReq) response2.WafAnalysisDetailResp {
	day := analysisDay(req.Day)
	limit := analysisLimit(req.Limit, analysisDetailLimit)
	resp := response2.WafAnalysisDetailResp{Kind: req.Kind, Key: req.Key}
	statsDB := global.GWAF_LOCAL_STATS_DB
	if statsDB == nil || strings.TrimSpace(req.Key) == "" {
		return resp
	}

	var totals struct {
		ReqCnt    int64
		DenyCnt   int64
		Err4xxCnt int64
	}
	if req.Kind == "path" {
		resp.Actors = []response2.WafAnalysisDetailActor{}
		resp.Rules = []response2.WafAnalysisDetailRule{}

		receiver.scoped(statsDB.Model(&model.StatsActorPathDay{}), day, req.HostCode).
			Where("path_norm = ?", req.Key).
			Select("sum(req_cnt) as req_cnt, sum(deny_cnt) as deny_cnt, sum(err4xx_cnt) as err4xx_cnt").
			Scan(&totals)

		receiver.scoped(statsDB.Model(&model.StatsActorPathDay{}), day, req.HostCode).
			Where("path_norm = ?", req.Key).
			Select("actor_key, sum(req_cnt) as req_cnt, sum(deny_cnt) as deny_cnt, sum(err4xx_cnt) as err4xx_cnt").
			Group("actor_key").Order("req_cnt desc").Limit(limit).Scan(&resp.Actors)

		receiver.scoped(statsDB.Model(&model.StatsPathRuleDay{}), day, req.HostCode).
			Where("path_norm = ?", req.Key).
			Select("rule, sum(cnt) as cnt").Group("rule").Order("cnt desc").Limit(limit).Scan(&resp.Rules)
	} else {
		resp.Kind = "actor"
		resp.Paths = []response2.WafAnalysisDetailPath{}
		resp.Uas = []response2.WafAnalysisDetailUa{}
		resp.Hosts = []response2.WafAnalysisDetailHost{}

		receiver.scoped(statsDB.Model(&model.StatsActorPathDay{}), day, req.HostCode).
			Where("actor_key = ?", req.Key).
			Select("sum(req_cnt) as req_cnt, sum(deny_cnt) as deny_cnt, sum(err4xx_cnt) as err4xx_cnt").
			Scan(&totals)

		receiver.scoped(statsDB.Model(&model.StatsActorPathDay{}), day, req.HostCode).
			Where("actor_key = ?", req.Key).
			Select("path_norm, sum(req_cnt) as req_cnt, sum(deny_cnt) as deny_cnt, sum(err4xx_cnt) as err4xx_cnt").
			Group("path_norm").Order("req_cnt desc").Limit(limit).Scan(&resp.Paths)

		receiver.scoped(statsDB.Model(&model.StatsActorUaDay{}), day, req.HostCode).
			Where("actor_key = ?", req.Key).
			Select("ua_hash, sum(cnt) as cnt").Group("ua_hash").Order("cnt desc").Limit(limit).Scan(&resp.Uas)

		// 站点维度：加黑/加白的 host_code 是必填，界面靠它给用户选，别在前端瞎猜
		receiver.scoped(statsDB.Model(&model.StatsActorPathDay{}), day, req.HostCode).
			Where("actor_key = ?", req.Key).
			Select("host_code, sum(req_cnt) as req_cnt, sum(deny_cnt) as deny_cnt").
			Group("host_code").Order("req_cnt desc").Limit(limit).Scan(&resp.Hosts)
	}
	resp.ReqCnt, resp.DenyCnt, resp.Err4xxCnt = totals.ReqCnt, totals.DenyCnt, totals.Err4xxCnt
	return resp
}
