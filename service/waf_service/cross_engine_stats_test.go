//go:build crossdb

// stats 库三库回归：验证统计聚合（sum/group by 等方言 SQL）+ 结构化 SQL 查询
// 在 SQLite/MySQL/PostgreSQL 上都能执行且结果合理。由 TestCrossEngine 每引擎调一次。
package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/model"
	req "SamWaf/model/request"
	"strconv"
	"testing"
	"time"

	"gorm.io/gorm"
)

func runStatsCases(t *testing.T, statsdb *gorm.DB) {
	today := time.Now().Format("20060102")
	dayInt, _ := strconv.Atoi(today)

	// 种子：今日 StatsDay（阻止 5、放行 10）
	must(t, statsdb.Create(&model.StatsDay{BaseOrm: newBase(uuid.GenUUID()), HostCode: "h1", Host: "a.com", Day: dayInt, Type: "阻止", Count: 5}).Error)
	must(t, statsdb.Create(&model.StatsDay{BaseOrm: newBase(uuid.GenUUID()), HostCode: "h1", Host: "a.com", Day: dayInt, Type: "放行", Count: 10}).Error)
	// 种子：今日站点统计
	must(t, statsdb.Create(&model.StatsSiteDay{BaseOrm: newBase(uuid.GenUUID()), HostCode: "h1", Host: "a.com", Day: dayInt, TotalCount: 15, AttackCount: 5, NormalCount: 10}).Error)

	t.Run("StatHomeSumDay", func(t *testing.T) {
		res, err := WafStatServiceApp.StatHomeSumDayApi()
		fatalIf(t, err)
		if res.AttackCountOfToday != 5 {
			t.Fatalf("今日攻击数聚合期望 5，实际 %d", res.AttackCountOfToday)
		}
	})

	t.Run("StatHomeSumDayRange", func(t *testing.T) {
		_, err := WafStatServiceApp.StatHomeSumDayRangeApi(req.WafStatsDayRangeReq{StartDay: today, EndDay: today})
		fatalIf(t, err) // 只验证聚合 SQL 在三方言可执行，不崩即可
	})

	t.Run("StatHomeSumDayTopIPRange", func(t *testing.T) {
		_, err := WafStatServiceApp.StatHomeSumDayTopIPRangeApi(req.WafStatsDayRangeReq{StartDay: today, EndDay: today})
		fatalIf(t, err)
	})

	t.Run("StatSiteOverview", func(t *testing.T) {
		_, err := WafStatServiceApp.StatSiteOverviewApi(req.WafStatsSiteOverviewReq{StartDay: today, EndDay: today})
		fatalIf(t, err)
	})

	// 结构化 SQL 查询（动态选库 + 列白名单），对 stats 库 stats_days 计数
	t.Run("SqlQuery_Count", func(t *testing.T) {
		_, err := WafSqlQueryServiceApp.ExecuteQuery(req.WafSqlQueryReq{
			DbType: "stats", Table: "stats_days", Mode: "count",
		})
		fatalIf(t, err)
	})
}
