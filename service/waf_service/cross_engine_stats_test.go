//go:build crossdb

// stats 库三库回归：验证统计聚合（sum/group by 等方言 SQL）+ 结构化 SQL 查询
// 在 SQLite/MySQL/PostgreSQL 上都能执行且结果正确。由 TestCrossEngine 每引擎调一次。
//
// 注意：这里的断言必须校验**返回值**而不只是 err。历史上 StatSiteOverviewApi 吞掉了
// 所有 Scan 错误恒返回 nil，导致 ONLY_FULL_GROUP_BY 违规（SELECT 非聚合列 host +
// GROUP BY host_code）在 MySQL/PG 上静默返回空列表却测试全绿。
package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/model"
	req "SamWaf/model/request"
	response2 "SamWaf/model/response"
	"strconv"
	"testing"
	"time"

	"gorm.io/gorm"
)

// findSite 从站点概览列表里按 host_code 取出一项
func findSite(t *testing.T, list []response2.WafSiteStatDetail, hostCode string) response2.WafSiteStatDetail {
	t.Helper()
	for _, d := range list {
		if d.HostCode == hostCode {
			return d
		}
	}
	t.Fatalf("站点概览里找不到 host_code=%s（实际 %d 项）", hostCode, len(list))
	return response2.WafSiteStatDetail{}
}

func eq64(t *testing.T, what string, got, want int64) {
	t.Helper()
	if got != want {
		t.Fatalf("%s 期望 %d，实际 %d", what, want, got)
	}
}

func runStatsCases(t *testing.T, statsdb *gorm.DB) {
	now := time.Now()
	today := now.Format("20060102")
	yesterday := now.AddDate(0, 0, -1).Format("20060102")
	todayInt, _ := strconv.Atoi(today)
	yesterdayInt, _ := strconv.Atoi(yesterday)
	curHourTs := (now.Unix() / 3600) * 3600

	newStatsDay := func(hostCode, host string, day int, typ string, cnt int) *model.StatsDay {
		return &model.StatsDay{BaseOrm: newBase(uuid.GenUUID()), HostCode: hostCode, Host: host, Day: day, Type: typ, Count: cnt}
	}
	newIPDay := func(hostCode, host string, day int, ip, typ string, cnt int) *model.StatsIPDay {
		return &model.StatsIPDay{BaseOrm: newBase(uuid.GenUUID()), HostCode: hostCode, Host: host, Day: day, IP: ip, Type: typ, Count: cnt}
	}

	// —— 种子：StatsDay（今日 阻止5/放行10，昨日 阻止3）——
	must(t, statsdb.Create(newStatsDay("h1", "a.com", todayInt, "阻止", 5)).Error)
	must(t, statsdb.Create(newStatsDay("h1", "a.com", todayInt, "放行", 10)).Error)
	must(t, statsdb.Create(newStatsDay("h1", "a.com", yesterdayInt, "阻止", 3)).Error)

	// —— 种子：StatsSiteDay，h1 跨两天 + h2 一天 ——
	// h1 两天合计：total 20 / attack 6 / normal 14 / in 1536 / out 3072 / timeSpent 200
	must(t, statsdb.Create(&model.StatsSiteDay{BaseOrm: newBase(uuid.GenUUID()), HostCode: "h1", Host: "a.com", Day: todayInt,
		TotalCount: 15, AttackCount: 5, NormalCount: 10, TrafficIn: 1024, TrafficOut: 2048, TotalTimeSpent: 150}).Error)
	must(t, statsdb.Create(&model.StatsSiteDay{BaseOrm: newBase(uuid.GenUUID()), HostCode: "h1", Host: "a.com", Day: yesterdayInt,
		TotalCount: 5, AttackCount: 1, NormalCount: 4, TrafficIn: 512, TrafficOut: 1024, TotalTimeSpent: 50}).Error)
	must(t, statsdb.Create(&model.StatsSiteDay{BaseOrm: newBase(uuid.GenUUID()), HostCode: "h2", Host: "b.com", Day: todayInt,
		TotalCount: 3, AttackCount: 0, NormalCount: 3, TrafficIn: 128, TrafficOut: 256, TotalTimeSpent: 30}).Error)

	// —— 种子：StatsSiteHour（当前整点，供 24h 趋势用）——
	must(t, statsdb.Create(&model.StatsSiteHour{BaseOrm: newBase(uuid.GenUUID()), HostCode: "h1", Host: "a.com", HourTime: curHourTs,
		TotalCount: 8, AttackCount: 2, NormalCount: 6, TrafficIn: 64, TrafficOut: 128, TotalTimeSpent: 80}).Error)

	// —— 种子：StatsIPDay（此前套件从未种过，聚合一直跑在空表上）——
	// h1 今日去重 IP = {1.1.1.1, 2.2.2.2} = 2；h1 两天去重 = 再加 3.3.3.3 = 3；h2 今日 = 1
	must(t, statsdb.Create(newIPDay("h1", "a.com", todayInt, "1.1.1.1", "阻止", 3)).Error)
	must(t, statsdb.Create(newIPDay("h1", "a.com", todayInt, "2.2.2.2", "阻止", 2)).Error)
	must(t, statsdb.Create(newIPDay("h1", "a.com", todayInt, "1.1.1.1", "放行", 7)).Error)
	must(t, statsdb.Create(newIPDay("h1", "a.com", yesterdayInt, "3.3.3.3", "阻止", 1)).Error)
	must(t, statsdb.Create(newIPDay("h2", "b.com", todayInt, "4.4.4.4", "放行", 3)).Error)

	t.Run("StatHomeSumDay", func(t *testing.T) {
		res, err := WafStatServiceApp.StatHomeSumDayApi()
		fatalIf(t, err)
		eq64(t, "今日攻击数", res.AttackCountOfToday, 5)
		eq64(t, "今日访问数", res.VisitCountOfToday, 15)
		eq64(t, "昨日攻击数", res.AttackCountOfYesterday, 3)
		// 去重 IP：今日放行 {1.1.1.1, 4.4.4.4}=2，今日阻止 {1.1.1.1, 2.2.2.2}=2
		eq64(t, "今日放行去重IP数", res.NormalIpCountOfToday, 2)
		eq64(t, "今日拦截去重IP数", res.IllegalIpCountOfToday, 2)
	})

	t.Run("StatHomeSumDayRange", func(t *testing.T) {
		res, err := WafStatServiceApp.StatHomeSumDayRangeApi(req.WafStatsDayRangeReq{StartDay: yesterday, EndDay: today})
		fatalIf(t, err)
		eq64(t, "区间今日攻击数", res.AttackCountOfRange[todayInt], 5)
		eq64(t, "区间昨日攻击数", res.AttackCountOfRange[yesterdayInt], 3)
		eq64(t, "区间今日放行数", res.NormalCountOfRange[todayInt], 10)
	})

	t.Run("StatHomeSumDayTopIPRange", func(t *testing.T) {
		res, err := WafStatServiceApp.StatHomeSumDayTopIPRangeApi(req.WafStatsDayRangeReq{StartDay: yesterday, EndDay: today})
		fatalIf(t, err)
		if len(res.AttackIPOfRange) != 3 {
			t.Fatalf("攻击 TopIP 期望 3 条，实际 %d", len(res.AttackIPOfRange))
		}
		// 按 sum(count) 倒序，1.1.1.1(3) 居首
		if res.AttackIPOfRange[0].IP != "1.1.1.1" || res.AttackIPOfRange[0].Count != 3 {
			t.Fatalf("攻击 TopIP 首位期望 1.1.1.1/3，实际 %s/%d", res.AttackIPOfRange[0].IP, res.AttackIPOfRange[0].Count)
		}
		if len(res.NormalIPOfRange) != 2 {
			t.Fatalf("放行 TopIP 期望 2 条，实际 %d", len(res.NormalIPOfRange))
		}
	})

	// 本次 #896 回归点：SELECT 非聚合列 host + GROUP BY host_code，
	// 在 MySQL(ONLY_FULL_GROUP_BY)/PostgreSQL 上会直接报错，必须用聚合函数取值。
	t.Run("StatSiteOverview", func(t *testing.T) {
		res, err := WafStatServiceApp.StatSiteOverviewApi(req.WafStatsSiteOverviewReq{StartDay: yesterday, EndDay: today})
		fatalIf(t, err)
		if len(res.SiteList) != 2 {
			t.Fatalf("站点概览期望 2 个站点，实际 %d", len(res.SiteList))
		}
		// 按 PV 倒序，h1(20) 在 h2(3) 之前
		if res.SiteList[0].HostCode != "h1" {
			t.Fatalf("站点概览应按 PV 倒序，首位期望 h1，实际 %s", res.SiteList[0].HostCode)
		}
		h1 := findSite(t, res.SiteList, "h1")
		if h1.Host != "a.com" {
			t.Fatalf("h1 域名期望 a.com，实际 %q", h1.Host)
		}
		eq64(t, "h1 两天 PV", h1.TotalCount, 20)
		eq64(t, "h1 两天拦截", h1.AttackCount, 6)
		eq64(t, "h1 两天放行", h1.NormalCount, 14)
		eq64(t, "h1 两天去重IP(UV)", h1.UvCount, 3)
		if h1.AvgTimeMs != 10 { // 200ms / 20 次
			t.Fatalf("h1 平均耗时期望 10ms，实际 %v", h1.AvgTimeMs)
		}
		eq64(t, "总 PV", res.TotalPv, 23)
		eq64(t, "总拦截", res.TotalAttack, 6)
		eq64(t, "总 UV", res.TotalUv, 4)
	})

	t.Run("GetTodaySiteStatsByHostCodes", func(t *testing.T) {
		m := WafStatServiceApp.GetTodaySiteStatsByHostCodes([]string{"h1", "h2"})
		if len(m) != 2 {
			t.Fatalf("今日站点统计期望 2 项，实际 %d", len(m))
		}
		eq64(t, "h1 今日 PV", m["h1"].TodayPvCount, 15)
		eq64(t, "h1 今日拦截", m["h1"].TodayAttackCount, 5)
		eq64(t, "h1 今日 UV", m["h1"].TodayUvCount, 2)
		eq64(t, "h1 今日入流量", m["h1"].TodayTrafficIn, 1024)
		eq64(t, "h2 今日 PV", m["h2"].TodayPvCount, 3)
	})

	t.Run("StatSiteDetail_7d", func(t *testing.T) {
		res, err := WafStatServiceApp.StatSiteDetailApi(req.WafStatsSiteDetailReq{HostCode: "h1", TimeRange: "7d"})
		fatalIf(t, err)
		if len(res.DayTrend) != 2 {
			t.Fatalf("7d 趋势期望 2 天，实际 %d", len(res.DayTrend))
		}
		if res.DayTrend[0].Day != yesterdayInt || res.DayTrend[1].Day != todayInt {
			t.Fatalf("7d 趋势应按天升序，实际 %d,%d", res.DayTrend[0].Day, res.DayTrend[1].Day)
		}
		eq64(t, "7d 昨日 UV", res.DayTrend[0].UvCount, 1)
		eq64(t, "7d 今日 UV", res.DayTrend[1].UvCount, 2)
		eq64(t, "7d 总请求", res.TotalCountSum, 20)
	})

	t.Run("StatSiteDetail_24h", func(t *testing.T) {
		res, err := WafStatServiceApp.StatSiteDetailApi(req.WafStatsSiteDetailReq{HostCode: "h1", TimeRange: "24h"})
		fatalIf(t, err)
		if len(res.HourTrend) != 24 {
			t.Fatalf("24h 趋势期望 24 个点，实际 %d", len(res.HourTrend))
		}
		eq64(t, "24h 总请求", res.TotalCountSum, 8)
		eq64(t, "24h 总耗时", res.TotalTimeSpentSum, 80)
	})

	// 结构化 SQL 查询（动态选库 + 列白名单），对 stats 库 stats_days 计数
	t.Run("SqlQuery_Count", func(t *testing.T) {
		_, err := WafSqlQueryServiceApp.ExecuteQuery(req.WafSqlQueryReq{
			DbType: "stats", Table: "stats_days", Mode: "count",
		})
		fatalIf(t, err)
	})
}
