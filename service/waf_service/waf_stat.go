package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v4/host"
	"math"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type WafStatService struct{}

var WafStatServiceApp = new(WafStatService)

func (receiver *WafStatService) StatHomeSumDayApi() (response2.WafStat, error) {
	currentDay, _ := strconv.Atoi(time.Now().Format("20060102"))
	yesterdayDay, _ := strconv.Atoi(time.Now().AddDate(0, 0, -1).Format("20060102"))

	// 空表时 sum() 返回 NULL，直接 Scan 进 int64 会报 "converting NULL to int64"，
	// 用 coalesce 兜底成 0（sqlite/mysql/pg 通用），这样错误才能真实反映方言问题。
	var AttackCountOfToday int64
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).Where("day = ? and type = ? ",
		currentDay, "阻止").Select("coalesce(sum(count),0) as vcnt").Row().Scan(&AttackCountOfToday); err != nil {
		return response2.WafStat{}, err
	}

	var VisitCountOfToday int64
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).Where("day = ? ",
		currentDay).Select("coalesce(sum(count),0) as vcnt").Row().Scan(&VisitCountOfToday); err != nil {
		return response2.WafStat{}, err
	}

	var AttackCountOfYesterday int64
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).Where("day = ? and type = ? ",
		yesterdayDay, "阻止").Select("coalesce(sum(count),0) as vcnt").Row().Scan(&AttackCountOfYesterday); err != nil {
		return response2.WafStat{}, err
	}

	var VisitCountOfYesterday int64
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).Where("day = ? ",
		yesterdayDay).Select("coalesce(sum(count),0) as vcnt").Row().Scan(&VisitCountOfYesterday); err != nil {
		return response2.WafStat{}, err
	}

	// 去重IP数用 count(distinct ip)：老写法 Group("ip")+Count 靠 RowsAffected 取分组数，
	// 数据库要把每个IP各回一行（单日20万IP就是20万行），走远程 MySQL/PG 时网络开销很可观。
	var NormalIpCountOfToday int64
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).Where("day = ? and type = ? ",
		currentDay, "放行").Select("count(distinct ip)").Scan(&NormalIpCountOfToday).Error; err != nil {
		return response2.WafStat{}, err
	}

	var IllegalIpCountOfToday int64
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).Where("day = ? and type = ? ",
		currentDay, "阻止").Select("count(distinct ip)").Scan(&IllegalIpCountOfToday).Error; err != nil {
		return response2.WafStat{}, err
	}
	// 同期环比（失败不影响卡片本身的数字，只是不显示对比）
	attackCompare, visitCompare, illegalIpCompare, compareHours := receiver.buildDayCompare(time.Now())

	return response2.WafStat{
			AttackCountOfToday:          AttackCountOfToday,
			VisitCountOfToday:           VisitCountOfToday,
			AttackCountOfYesterday:      AttackCountOfYesterday,
			VisitCountOfYesterday:       VisitCountOfYesterday,
			AttackCountOfLastWeekToday:  0,
			VisitCountOfLastWeekToday:   0,
			NormalIpCountOfToday:        NormalIpCountOfToday,
			IllegalIpCountOfToday:       IllegalIpCountOfToday,
			NormalCountryCountOfToday:   0,
			IllegalCountryCountOfToday:  0,
			NormalProvinceCountOfToday:  0,
			IllegalProvinceCountOfToday: 0,
			NormalCityCountOfToday:      0,
			IllegalCityCountOfToday:     0,
			CurrentQps:                  global.GetRealtimeQPS(),
			CompareHours:                compareHours,
			AttackCompare:               attackCompare,
			VisitCompare:                visitCompare,
			IllegalIpCompare:            illegalIpCompare,
		},
		nil
}

// buildDayCompare 计算首页三张卡片的"较昨日同期"。
//
// 窗口取今天已经走完的整点小时数 hours：今天 [00:00, hours:00) 对比昨天 [00:00, hours:00)。
// 攻击/访问量走小时级统计表；异常IP没有小时表，改用 stats_ip_day 的 create_time —— 该行是
// 这个IP当天第一次被记录时创建的，所以 create_time < T 的去重IP数就等于当天 T 之前出现过的IP数。
//
// 任一步出错都只降级成"无对比"，不让首页数字整体失败。
func (receiver *WafStatService) buildDayCompare(now time.Time) (attack, visit, illegalIp response2.WafStatCompare, hours int) {
	hours = now.Hour()
	if hours == 0 {
		// 刚过零点不足1小时，没有可比的窗口
		return
	}
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	yesterdayStart := todayStart.AddDate(0, 0, -1)
	window := int64(hours) * 3600

	type hourSum struct {
		AttackCount int64
		TotalCount  int64
	}
	sumHour := func(start time.Time) (hourSum, error) {
		var s hourSum
		err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteHour{}).
			Where("hour_time >= ? and hour_time < ?", start.Unix(), start.Unix()+window).
			Select("coalesce(sum(attack_count),0) as attack_count,coalesce(sum(total_count),0) as total_count").
			Scan(&s).Error
		return s, err
	}
	// 走 idx_stats_ip_days_day_type_ct(day,type,create_time,ip) 覆盖索引，
	// 50万行实测 900ms -> 170ms
	countIllegalIP := func(day int, before time.Time) (int64, error) {
		var c int64
		err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
			Where("day = ? and type = ? and create_time < ?", day, "阻止", before).
			Select("count(distinct ip)").Scan(&c).Error
		return c, err
	}

	todayHour, err := sumHour(todayStart)
	if err != nil {
		zlog.Error("统计今日同期小时数据失败", err)
		return
	}
	yesterdayHour, err := sumHour(yesterdayStart)
	if err != nil {
		zlog.Error("统计昨日同期小时数据失败", err)
		return
	}
	attack = buildCompare(todayHour.AttackCount, yesterdayHour.AttackCount)
	visit = buildCompare(todayHour.TotalCount, yesterdayHour.TotalCount)

	todayDay, _ := strconv.Atoi(todayStart.Format("20060102"))
	yesterdayDay, _ := strconv.Atoi(yesterdayStart.Format("20060102"))
	todayIP, err := countIllegalIP(todayDay, todayStart.Add(time.Duration(window)*time.Second))
	if err != nil {
		zlog.Error("统计今日同期异常IP失败", err)
		return
	}
	yesterdayIP, err := countIllegalIP(yesterdayDay, yesterdayStart.Add(time.Duration(window)*time.Second))
	if err != nil {
		zlog.Error("统计昨日同期异常IP失败", err)
		return
	}
	illegalIp = buildCompare(todayIP, yesterdayIP)
	return
}

// buildCompare 由今日/昨日同期值算出变化百分比
func buildCompare(cur, prev int64) response2.WafStatCompare {
	c := response2.WafStatCompare{HasCompare: true, Current: cur, Previous: prev, Trend: "flat"}
	switch {
	case prev == 0 && cur == 0:
		return c
	case prev == 0:
		c.Percent = 100
		c.Trend = "up"
		return c
	}
	c.Percent = math.Round(float64(cur-prev)/float64(prev)*1000) / 10
	if c.Percent > 0 {
		c.Trend = "up"
	} else if c.Percent < 0 {
		c.Trend = "down"
	}
	return c
}

// StatQpsTrendApi 取最近的QPS采样(内存环形缓冲)
func (receiver *WafStatService) StatQpsTrendApi(limit int) response2.WafQpsTrend {
	samples := global.GetQPSHistory(limit)
	points := make([]response2.WafQpsTrendPoint, 0, len(samples))
	var max uint64
	for _, s := range samples {
		points = append(points, response2.WafQpsTrendPoint{T: s.T, V: s.V})
		if s.V > max {
			max = s.V
		}
	}
	return response2.WafQpsTrend{
		Current: global.GetRealtimeQPS(),
		Max:     max,
		Points:  points,
	}
}

func (receiver *WafStatService) StatHomeSumDayRangeApi(req request.WafStatsDayRangeReq) (response2.WafStatRange, error) {
	var rangeAttackMap = map[int]int64{}
	var rangeNormalMap = map[int]int64{}
	var rangeInt = (int)(utils.Str2Time(req.EndDay).Sub(utils.Str2Time(req.StartDay)).Hours() / 24)

	for i := 0; i <= rangeInt; i++ {
		rangeAttackMap[utils.TimeToDayInt(utils.Str2Time(req.StartDay).AddDate(0, 0, i))] = 0
		rangeNormalMap[utils.TimeToDayInt(utils.Str2Time(req.StartDay).AddDate(0, 0, i))] = 0
	}

	var AttackCountOfRange []model.StatsDayCount
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).Where("day between ? and ? and type = ? ",
		req.StartDay, req.EndDay, "阻止").Select("day,sum(count) as count").Group("day").Scan(&AttackCountOfRange).Error; err != nil {
		return response2.WafStatRange{}, err
	}
	var NormalCountOfRange []model.StatsDayCount
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).Where("day between ? and ? and type = ? ",
		req.StartDay, req.EndDay, "放行").Select("day,sum(count) as count").Group("day").Scan(&NormalCountOfRange).Error; err != nil {
		return response2.WafStatRange{}, err
	}

	for i := 0; i < len(AttackCountOfRange); i++ {
		bean := AttackCountOfRange[i]
		_, ok := rangeAttackMap[bean.Day]
		if ok {
			rangeAttackMap[bean.Day] = bean.Count
		}
	}
	for i := 0; i < len(NormalCountOfRange); i++ {
		bean := NormalCountOfRange[i]
		_, ok := rangeNormalMap[bean.Day]
		if ok {
			rangeNormalMap[bean.Day] = bean.Count
		}
	}
	return response2.WafStatRange{
			AttackCountOfRange: rangeAttackMap,
			NormalCountOfRange: rangeNormalMap,
		},
		nil
}
func (receiver *WafStatService) StatHomeSumDayTopIPRangeApi(req request.WafStatsDayRangeReq) (response2.WafIPStats, error) {
	var AttackCountOfRange []model.StatsIPCount
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
		Where("day between ? and ? and type = ? ", req.StartDay, req.EndDay, "阻止").
		Select("ip,sum(count) as count").Group("ip").Order("sum(count) desc").
		Limit(10).
		Scan(&AttackCountOfRange).Error; err != nil {
		return response2.WafIPStats{}, err
	}

	var AttackCountOfRangeMore []model.StatsIPCountMore
	ipTagDB := global.GetIPTagDB() // 使用封装方法获取数据库连接
	for i := range AttackCountOfRange {
		region := utils.GetCountry(AttackCountOfRange[i].IP)
		//查询IP标签
		var ipTags []model.IPTag
		ipTagDB.Where("tenant_id = ? and user_code = ? and ip=?",
			global.GWAF_TENANT_ID, global.GWAF_USER_CODE, AttackCountOfRange[i].IP).Find(&ipTags)

		statMore := model.StatsIPCountMore{
			IP:       AttackCountOfRange[i].IP,
			IPBelong: region[0],
			IPTag:    ipTags,
			Count:    AttackCountOfRange[i].Count,
		}
		AttackCountOfRangeMore = append(AttackCountOfRangeMore, statMore)
	}

	var NormalCountOfRange []model.StatsIPCount
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
		Where("day between ? and ? and type = ? ",
			req.StartDay, req.EndDay, "放行").Select("ip,sum(count) as count").
		Group("ip").Order("sum(count) desc").
		Limit(10).
		Scan(&NormalCountOfRange).Error; err != nil {
		return response2.WafIPStats{}, err
	}

	var NormalCountOfRangeMore []model.StatsIPCountMore
	for i := range NormalCountOfRange {
		region := utils.GetCountry(NormalCountOfRange[i].IP)
		NormalCountOfRange[i].IPBelong = region[0]

		//查询IP标签
		var ipTags []model.IPTag
		ipTagDB.Where("tenant_id = ? and user_code = ? and ip=?",
			global.GWAF_TENANT_ID, global.GWAF_USER_CODE, NormalCountOfRange[i].IP).Find(&ipTags)

		statMore := model.StatsIPCountMore{
			IP:       NormalCountOfRange[i].IP,
			IPBelong: region[0],
			IPTag:    ipTags,
			Count:    NormalCountOfRange[i].Count,
		}
		NormalCountOfRangeMore = append(NormalCountOfRangeMore, statMore)
	}
	return response2.WafIPStats{
			AttackIPOfRange: AttackCountOfRangeMore,
			NormalIPOfRange: NormalCountOfRangeMore,
		},
		nil
}

// 获取系统基本信息
func (receiver *WafStatService) StatHomeSysinfo(c *gin.Context) (response2.WafHomeSysinfoStat, error) {
	tokenStr := c.GetHeader("X-Token")
	tokenInfo := WafTokenInfoServiceApp.GetInfoByAccessToken(tokenStr)
	if tokenInfo.LoginAccount == "" {
		return response2.WafHomeSysinfoStat{}, errors.New("token可能已经失效")
	}
	return response2.WafHomeSysinfoStat{
		IsDefaultAccount: WafAccountServiceApp.IsExistDefaultAccount(),
		IsEmptyHost:      WafHostServiceApp.IsEmptyHost(),
		IsEmptyOtp:       WafOtpServiceApp.IsEmptyOtp(tokenInfo.LoginAccount),
	}, nil
}

// GetTodaySiteStatsByHostCodes 获取指定站点今天的 PV/UV/拦截数/吞吐量
func (receiver *WafStatService) GetTodaySiteStatsByHostCodes(hostCodes []string) map[string]response2.HostTodayStat {
	statsMap := make(map[string]response2.HostTodayStat)
	if len(hostCodes) == 0 {
		return statsMap
	}

	currentDay, _ := strconv.Atoi(time.Now().Format("20060102"))

	type siteRow struct {
		HostCode    string
		TotalCount  int64
		AttackCount int64
		TrafficIn   int64
		TrafficOut  int64
	}
	var siteRows []siteRow
	// 本方法无 error 返回值（列表页附带查询，查不到就不显示），但错误必须落日志，
	// 否则方言不兼容这类问题只会表现为"数字全是 0"而无从排查
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteDay{}).
		Where("day = ? and host_code in ?", currentDay, hostCodes).
		Select("host_code, sum(total_count) as total_count, sum(attack_count) as attack_count, sum(traffic_in) as traffic_in, sum(traffic_out) as traffic_out").
		Group("host_code").
		Scan(&siteRows).Error; err != nil {
		zlog.Error("查询今日站点统计失败", err)
	}

	for _, row := range siteRows {
		statsMap[row.HostCode] = response2.HostTodayStat{
			TodayPvCount:     row.TotalCount,
			TodayAttackCount: row.AttackCount,
			TodayTrafficIn:   row.TrafficIn,
			TodayTrafficOut:  row.TrafficOut,
		}
	}

	type uvRow struct {
		HostCode string
		UvCount  int64
	}
	var uvRows []uvRow
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
		Where("day = ? and host_code in ?", currentDay, hostCodes).
		Select("host_code, count(distinct ip) as uv_count").
		Group("host_code").
		Scan(&uvRows).Error; err != nil {
		zlog.Error("查询今日站点UV失败", err)
	}

	for _, row := range uvRows {
		stat := statsMap[row.HostCode]
		stat.TodayUvCount = row.UvCount
		statsMap[row.HostCode] = stat
	}

	return statsMap
}

// StatSiteOverviewApi 站点综合概览（按天范围查询，完全不依赖 web_logs）
func (receiver *WafStatService) StatSiteOverviewApi(req request.WafStatsSiteOverviewReq) (response2.WafSiteOverview, error) {
	// 1) 从 StatsSiteDay 按 host_code 聚合
	type siteRow struct {
		HostCode       string
		Host           string
		TotalCount     int64
		AttackCount    int64
		NormalCount    int64
		TrafficIn      int64
		TrafficOut     int64
		TotalTimeSpent int64
	}
	var rows []siteRow
	// host 是 host_code 的域名快照，语义上一对一，但 MySQL(ONLY_FULL_GROUP_BY)/PostgreSQL
	// 不允许 SELECT 非聚合列，必须用 max() 取值；若改成 group by host_code,host，
	// 站点在区间内改过域名时会被拆成多行，前端出现重复站点。
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteDay{}).
		Where("day between ? and ?", req.StartDay, req.EndDay).
		Select("host_code, max(host) as host, sum(total_count) as total_count, sum(attack_count) as attack_count, sum(normal_count) as normal_count, sum(traffic_in) as traffic_in, sum(traffic_out) as traffic_out, sum(total_time_spent) as total_time_spent").
		Group("host_code").
		Order("sum(total_count) desc").
		Scan(&rows).Error; err != nil {
		return response2.WafSiteOverview{}, err
	}

	// 2) 根据 host_code 回填站点备注
	type hostRemarkRow struct {
		Code    string
		Remarks string
	}
	hostCodes := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.HostCode == "" {
			continue
		}
		hostCodes = append(hostCodes, r.HostCode)
	}
	hostRemarkMap := make(map[string]string)
	if len(hostCodes) > 0 {
		var hostRows []hostRemarkRow
		if err := global.GWAF_LOCAL_DB.Model(&model.Hosts{}).
			Where("code in ?", hostCodes).
			Select("code, remarks").
			Scan(&hostRows).Error; err != nil {
			return response2.WafSiteOverview{}, err
		}
		for _, r := range hostRows {
			hostRemarkMap[r.Code] = r.Remarks
		}
	}

	// 3) 从 StatsIPDay 按 host_code 查 UV/IP 数
	type uvRow struct {
		HostCode string
		UvCount  int64
	}
	var uvRows []uvRow
	if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
		Where("day between ? and ?", req.StartDay, req.EndDay).
		Select("host_code, count(distinct ip) as uv_count").
		Group("host_code").
		Scan(&uvRows).Error; err != nil {
		return response2.WafSiteOverview{}, err
	}
	uvMap := make(map[string]int64)
	for _, r := range uvRows {
		uvMap[r.HostCode] = r.UvCount
	}

	// 4) 组装结果
	var overview response2.WafSiteOverview
	for _, r := range rows {
		uv := uvMap[r.HostCode]
		var avgMs float64
		if r.TotalCount > 0 {
			avgMs = float64(r.TotalTimeSpent) / float64(r.TotalCount)
		}
		detail := response2.WafSiteStatDetail{
			HostCode:     r.HostCode,
			Host:         r.Host,
			HostRemark:   hostRemarkMap[r.HostCode],
			TotalCount:   r.TotalCount,
			AttackCount:  r.AttackCount,
			NormalCount:  r.NormalCount,
			TrafficInMb:  float64(r.TrafficIn) / 1024 / 1024,
			TrafficOutMb: float64(r.TrafficOut) / 1024 / 1024,
			UvCount:      uv,
			IpCount:      uv,
			AvgTimeMs:    avgMs,
		}
		overview.SiteList = append(overview.SiteList, detail)
		overview.TotalPv += r.TotalCount
		overview.TotalAttack += r.AttackCount
		overview.TotalUv += uv
		overview.TotalIp += uv
		overview.TotalInMb += detail.TrafficInMb
		overview.TotalOutMb += detail.TrafficOutMb
	}
	if overview.SiteList == nil {
		overview.SiteList = []response2.WafSiteStatDetail{}
	}
	return overview, nil
}

// StatSiteDetailApi 站点详情趋势（完全不查 web_logs，小时/天级预聚合）
func (receiver *WafStatService) StatSiteDetailApi(req request.WafStatsSiteDetailReq) (response2.WafSiteDetail, error) {
	detail := response2.WafSiteDetail{
		HostCode:  req.HostCode,
		HourTrend: []response2.WafSiteHourPoint{},
		DayTrend:  []response2.WafSiteDayPoint{},
	}

	now := time.Now()
	switch req.TimeRange {
	case "1h":
		// 最近1小时，按小时查（最多2个点：上一整点+当前整点）
		startTs := (now.Add(-1*time.Hour).Unix() / 3600) * 3600
		var pts []model.StatsSiteHour
		if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteHour{}).
			Where("host_code = ? and hour_time >= ?", req.HostCode, startTs).
			Order("hour_time asc").Scan(&pts).Error; err != nil {
			return response2.WafSiteDetail{}, err
		}

		ptMap := make(map[int64]model.StatsSiteHour)
		for _, p := range pts {
			ptMap[p.HourTime] = p
		}

		currentTs := (now.Unix() / 3600) * 3600
		for ts := startTs; ts <= currentTs; ts += 3600 {
			if p, ok := ptMap[ts]; ok {
				detail.HourTrend = append(detail.HourTrend, response2.WafSiteHourPoint{
					HourTime: p.HourTime, TotalCount: p.TotalCount,
					AttackCount: p.AttackCount, NormalCount: p.NormalCount,
				})
				detail.TotalTimeSpentSum += p.TotalTimeSpent
				detail.TotalCountSum += p.TotalCount
			} else {
				detail.HourTrend = append(detail.HourTrend, response2.WafSiteHourPoint{
					HourTime: ts, TotalCount: 0, AttackCount: 0, NormalCount: 0,
				})
			}
		}
	case "24h":
		// 最近24小时，按小时查（最多24个点：过去23小时+当前整点）
		startTs := (now.Add(-23*time.Hour).Unix() / 3600) * 3600
		var pts []model.StatsSiteHour
		if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteHour{}).
			Where("host_code = ? and hour_time >= ?", req.HostCode, startTs).
			Order("hour_time asc").Scan(&pts).Error; err != nil {
			return response2.WafSiteDetail{}, err
		}

		ptMap := make(map[int64]model.StatsSiteHour)
		for _, p := range pts {
			ptMap[p.HourTime] = p
		}

		currentTs := (now.Unix() / 3600) * 3600
		for ts := startTs; ts <= currentTs; ts += 3600 {
			if p, ok := ptMap[ts]; ok {
				detail.HourTrend = append(detail.HourTrend, response2.WafSiteHourPoint{
					HourTime: p.HourTime, TotalCount: p.TotalCount,
					AttackCount: p.AttackCount, NormalCount: p.NormalCount,
				})
				detail.TotalTimeSpentSum += p.TotalTimeSpent
				detail.TotalCountSum += p.TotalCount
			} else {
				detail.HourTrend = append(detail.HourTrend, response2.WafSiteHourPoint{
					HourTime: ts, TotalCount: 0, AttackCount: 0, NormalCount: 0,
				})
			}
		}
	case "7d":
		startDay, _ := strconv.Atoi(now.AddDate(0, 0, -6).Format("20060102"))
		endDay, _ := strconv.Atoi(now.Format("20060102"))
		type dayRow struct {
			Day            int
			TotalCount     int64
			AttackCount    int64
			NormalCount    int64
			TotalTimeSpent int64
		}
		var dayRows []dayRow
		if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteDay{}).
			Where("host_code = ? and day between ? and ?", req.HostCode, startDay, endDay).
			Select("day, sum(total_count) as total_count, sum(attack_count) as attack_count, sum(normal_count) as normal_count, sum(total_time_spent) as total_time_spent").
			Group("day").Order("day asc").Scan(&dayRows).Error; err != nil {
			return response2.WafSiteDetail{}, err
		}
		// UV
		type uvDay struct {
			Day     int
			UvCount int64
		}
		var uvDays []uvDay
		if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
			Where("host_code = ? and day between ? and ?", req.HostCode, startDay, endDay).
			Select("day, count(distinct ip) as uv_count").
			Group("day").Order("day asc").Scan(&uvDays).Error; err != nil {
			return response2.WafSiteDetail{}, err
		}
		uvDayMap := make(map[int]int64)
		for _, u := range uvDays {
			uvDayMap[u.Day] = u.UvCount
		}
		for _, r := range dayRows {
			detail.DayTrend = append(detail.DayTrend, response2.WafSiteDayPoint{
				Day: r.Day, TotalCount: r.TotalCount,
				AttackCount: r.AttackCount, NormalCount: r.NormalCount,
				UvCount: uvDayMap[r.Day],
			})
			detail.TotalTimeSpentSum += r.TotalTimeSpent
			detail.TotalCountSum += r.TotalCount
		}
	case "30d":
		startDay, _ := strconv.Atoi(now.AddDate(0, 0, -29).Format("20060102"))
		endDay, _ := strconv.Atoi(now.Format("20060102"))
		type dayRow struct {
			Day            int
			TotalCount     int64
			AttackCount    int64
			NormalCount    int64
			TotalTimeSpent int64
		}
		var dayRows []dayRow
		if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteDay{}).
			Where("host_code = ? and day between ? and ?", req.HostCode, startDay, endDay).
			Select("day, sum(total_count) as total_count, sum(attack_count) as attack_count, sum(normal_count) as normal_count, sum(total_time_spent) as total_time_spent").
			Group("day").Order("day asc").Scan(&dayRows).Error; err != nil {
			return response2.WafSiteDetail{}, err
		}
		type uvDay struct {
			Day     int
			UvCount int64
		}
		var uvDays []uvDay
		if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
			Where("host_code = ? and day between ? and ?", req.HostCode, startDay, endDay).
			Select("day, count(distinct ip) as uv_count").
			Group("day").Order("day asc").Scan(&uvDays).Error; err != nil {
			return response2.WafSiteDetail{}, err
		}
		uvDayMap := make(map[int]int64)
		for _, u := range uvDays {
			uvDayMap[u.Day] = u.UvCount
		}
		for _, r := range dayRows {
			detail.DayTrend = append(detail.DayTrend, response2.WafSiteDayPoint{
				Day: r.Day, TotalCount: r.TotalCount,
				AttackCount: r.AttackCount, NormalCount: r.NormalCount,
				UvCount: uvDayMap[r.Day],
			})
			detail.TotalTimeSpentSum += r.TotalTimeSpent
			detail.TotalCountSum += r.TotalCount
		}
	default:
		// 默认 24h
		startTs := (now.Add(-23*time.Hour).Unix() / 3600) * 3600
		var pts []model.StatsSiteHour
		if err := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteHour{}).
			Where("host_code = ? and hour_time >= ?", req.HostCode, startTs).
			Order("hour_time asc").Scan(&pts).Error; err != nil {
			return response2.WafSiteDetail{}, err
		}

		ptMap := make(map[int64]model.StatsSiteHour)
		for _, p := range pts {
			ptMap[p.HourTime] = p
		}

		currentTs := (now.Unix() / 3600) * 3600
		for ts := startTs; ts <= currentTs; ts += 3600 {
			if p, ok := ptMap[ts]; ok {
				detail.HourTrend = append(detail.HourTrend, response2.WafSiteHourPoint{
					HourTime: p.HourTime, TotalCount: p.TotalCount,
					AttackCount: p.AttackCount, NormalCount: p.NormalCount,
				})
				detail.TotalTimeSpentSum += p.TotalTimeSpent
				detail.TotalCountSum += p.TotalCount
			} else {
				detail.HourTrend = append(detail.HourTrend, response2.WafSiteHourPoint{
					HourTime: ts, TotalCount: 0, AttackCount: 0, NormalCount: 0,
				})
			}
		}
	}

	// 计算平均响应时间和正常流量占比
	if detail.TotalCountSum > 0 {
		detail.AvgTimeMs = float64(detail.TotalTimeSpentSum) / float64(detail.TotalCountSum)
		// 从趋势数据累加 normal_count
		var totalNormal int64
		for _, p := range detail.HourTrend {
			totalNormal += p.NormalCount
		}
		for _, p := range detail.DayTrend {
			totalNormal += p.NormalCount
		}
		detail.NormalRatePercent = float64(totalNormal) / float64(detail.TotalCountSum) * 100
	}
	// 查询域名
	var siteDay model.StatsSiteDay
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteDay{}).
		Where("host_code = ?", req.HostCode).First(&siteDay)
	detail.Host = siteDay.Host

	return detail, nil
}

// 获取运行系统基本信息
func (receiver *WafStatService) StatHomeRumtimeSysinfo() []response2.WafNameValue {
	/*c, _ := cpu.Info()
	cc, _ := cpu.Percent(time.Second, false) // 1秒
	d, _ := disk.Usage("/")
	n, _ := host.Info()
	nv, _ := net.IOCounters(true)
	physicalCnt, _ := cpu.Counts(false)
	logicalCnt, _ := cpu.Counts(true)
	result := ""

	if len(c) > 1 {
		for _, sub_cpu := range c {
			modelname := sub_cpu.ModelName
			cores := sub_cpu.Cores
			result = result + fmt.Sprintf("CPUs: %v   %v cores \n", modelname, cores)
		}
	} else if len(c) ==1{
		sub_cpu := c[0]
		modelname := sub_cpu.ModelName
		cores := sub_cpu.Cores
		result = result + fmt.Sprintf("CPU: %v   %v cores \n", modelname, cores)
	}
	result = result + fmt.Sprintf("physical count:%d logical count:%d\n", physicalCnt, logicalCnt)
	result = result + fmt.Sprintf("CPU Used: used %f%%\n", cc[0])
	result = result + fmt.Sprintf("HD: %v GB Free: %v GB Usage:%f%%\n", d.Total/1024/1024/1024, d.Free/1024/1024/1024, d.UsedPercent)
	result = result + fmt.Sprintf("OS: %v(%v) %v\n", n.Platform, n.PlatformFamily, n.PlatformVersion)
	result = result + fmt.Sprintf("Hostname: %v\n", n.Hostname)
	result = result + fmt.Sprintf("Network: %v bytes / %v bytes\n", nv[0].BytesRecv, nv[0].BytesSent)
	*/
	var data []response2.WafNameValue
	//data = append(data, response2.WafNameValue{Name: "系统运行环境基本信息", Value: result})
	data = append(data, response2.WafNameValue{Name: "最后处理log时间",
		Value: time.Unix(0,
			global.GWAF_MEASURE_PROCESS_DEQUEENGINE.ReadData()*int64(time.Millisecond)).Format("2006-01-02 15:04:05")})
	data = append(data, response2.WafNameValue{Name: "Goroutine数量", Value: fmt.Sprintf("%v", runtime.NumGoroutine())})
	osDetail := utils.GetOSDetail()
	data = append(data, response2.WafNameValue{Name: "系统类型", Value: fmt.Sprintf("%v", runtime.GOOS)})
	data = append(data, response2.WafNameValue{Name: "系统架构", Value: fmt.Sprintf("%v", runtime.GOARCH)})
	// 具体操作系统发行版及版本，如 Ubuntu 24.04.1 LTS / Microsoft Windows Server 2012 R2 Standard
	if osDetail.OSName != "" {
		data = append(data, response2.WafNameValue{Name: "操作系统", Value: osDetail.OSName})
	}
	if osDetail.KernelVersion != "" {
		kernel := osDetail.KernelVersion
		if osDetail.KernelArch != "" {
			kernel = kernel + " (" + osDetail.KernelArch + ")"
		}
		data = append(data, response2.WafNameValue{Name: "内核版本", Value: kernel})
	}
	// 运行环境：容器/K8s/WSL/虚拟化，只有识别到才展示
	if env := describeRuntimeEnv(osDetail); env != "" {
		data = append(data, response2.WafNameValue{Name: "运行环境", Value: env})
	}
	data = append(data, response2.WafNameValue{Name: "编译器版本", Value: fmt.Sprintf("%v", runtime.Version())})
	// Win7内核只在 Windows 下才有意义，其它系统不展示
	if osDetail.IsWindows {
		data = append(data, response2.WafNameValue{Name: "Win7内核", Value: func() string {
			if global.GWAF_RUNTIME_WIN7_VERSION == "true" {
				return "是"
			}
			return "否"
		}()})
	}
	// 获取开机时间
	boottime, _ := host.BootTime()
	ntime := time.Now().Unix()
	btime := time.Unix(int64(boottime), 0).Unix()
	deltatime := ntime - btime
	// 将时间间隔转换为天、小时、分钟、秒
	seconds := int64(deltatime)
	minutes := seconds / 60
	seconds -= minutes * 60
	hours := minutes / 60
	minutes -= hours * 60
	days := hours / 24
	hours -= days * 24

	data = append(data, response2.WafNameValue{
		Name: "系统已运行时长", Value: fmt.Sprintf("%v 天 %v 时 %v 分 %v 秒", days, hours, minutes, seconds)})
	data = append(data, response2.WafNameValue{
		Name: "程序已运行时长", Value: utils.FormatDurationCN(int64(time.Since(global.GWAF_RUNTIME_PROCESS_START_TIME).Seconds()))})

	data = append(data, response2.WafNameValue{Name: "软件版本", Value: fmt.Sprintf("%v", global.GWAF_RELEASE_VERSION_NAME)})
	data = append(data, response2.WafNameValue{Name: "软件版本Code", Value: fmt.Sprintf("%v", global.GWAF_RELEASE_VERSION)})
	data = append(data, response2.WafNameValue{Name: "当前QPS", Value: fmt.Sprintf("%v", global.GetRealtimeQPS())})

	data = append(data, response2.WafNameValue{Name: "当前队列数", Value: fmt.Sprintf("主数据：%v 日志数据：%v  统计数据：%v  消息队列：%v", global.GQEQUE_DB.Size(), global.GQEQUE_LOG_DB.Size(), global.GQEQUE_STATS_DB.Size(), global.GQEQUE_MESSAGE_DB.Size())})
	data = append(data, response2.WafNameValue{Name: "当前日志队列处理QPS", Value: fmt.Sprintf("%v", global.GetRealtimeLogQPS())})
	data = append(data, response2.WafNameValue{Name: "当前web端口使用列表", Value: fmt.Sprintf("%v", global.GWAF_RUNTIME_CURRENT_WEBPORT)})
	data = append(data, response2.WafNameValue{Name: "当前隧道端口使用列表", Value: fmt.Sprintf("%v", global.GWAF_RUNTIME_CURRENT_TUNNELPORT)})

	return data
}

// describeRuntimeEnv 把容器/K8s/WSL/虚拟化信息拼成一句可读描述，都没识别到就返回空字符串
func describeRuntimeEnv(detail utils.OSDetail) string {
	var parts []string
	if detail.Container != "" {
		parts = append(parts, "容器("+detail.Container+")")
	}
	if detail.InKubernetes {
		parts = append(parts, "Kubernetes")
	}
	if detail.IsWSL {
		parts = append(parts, "WSL")
	}
	if detail.Virtualization != "" {
		parts = append(parts, "虚拟化("+detail.Virtualization+")")
	}
	return strings.Join(parts, " / ")
}
