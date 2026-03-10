package waf_service

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/host"
	"runtime"
	"strconv"
	"time"
)

type WafStatService struct{}

var WafStatServiceApp = new(WafStatService)

func (receiver *WafStatService) StatHomeSumDayApi() (response2.WafStat, error) {
	currentDay, _ := strconv.Atoi(time.Now().Format("20060102"))
	yesterdayDay, _ := strconv.Atoi(time.Now().AddDate(0, 0, -1).Format("20060102"))

	var AttackCountOfToday int64
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).Where("day = ? and type = ? ",
		currentDay, "阻止").Select("sum(count) as vcnt").Row().Scan(&AttackCountOfToday)

	var VisitCountOfToday int64
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).Where("day = ? ",
		currentDay).Select("sum(count) as vcnt").Row().Scan(&VisitCountOfToday)

	var AttackCountOfYesterday int64
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).Where("day = ? and type = ? ",
		yesterdayDay, "阻止").Select("sum(count) as vcnt").Row().Scan(&AttackCountOfYesterday)

	var VisitCountOfYesterday int64
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).Where("day = ? ",
		yesterdayDay).Select("sum(count) as vcnt").Row().Scan(&VisitCountOfYesterday)

	var NormalIpCountOfToday int64
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).Where("day = ? and type = ? ",
		currentDay, "放行").Group("ip").Count(&NormalIpCountOfToday)

	var IllegalIpCountOfToday int64
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).Where("day = ? and type = ? ",
		currentDay, "阻止").Group("ip").Count(&IllegalIpCountOfToday)
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
		},
		nil
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
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).Where("day between ? and ? and type = ? ",
		req.StartDay, req.EndDay, "阻止").Select("day,sum(count) as count").Group("day").Scan(&AttackCountOfRange)
	var NormalCountOfRange []model.StatsDayCount
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).Where("day between ? and ? and type = ? ",
		req.StartDay, req.EndDay, "放行").Select("day,sum(count) as count").Group("day").Scan(&NormalCountOfRange)

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
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
		Where("day between ? and ? and type = ? ", req.StartDay, req.EndDay, "阻止").
		Select("ip,sum(count) as count").Group("ip").Order("sum(count) desc").
		Limit(10).
		Scan(&AttackCountOfRange)

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
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
		Where("day between ? and ? and type = ? ",
			req.StartDay, req.EndDay, "放行").Select("ip,sum(count) as count").
		Group("ip").Order("sum(count) desc").
		Limit(10).
		Scan(&NormalCountOfRange)

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
func (receiver *WafStatService) StatHomeSysinfo(c *gin.Context) response2.WafHomeSysinfoStat {
	tokenStr := c.GetHeader("X-Token")
	tokenInfo := WafTokenInfoServiceApp.GetInfoByAccessToken(tokenStr)
	if tokenInfo.LoginAccount == "" {
		response.FailWithMessage("token可能已经失效", c)
		return response2.WafHomeSysinfoStat{}
	}
	return response2.WafHomeSysinfoStat{
		IsDefaultAccount: WafAccountServiceApp.IsExistDefaultAccount(),
		IsEmptyHost:      WafHostServiceApp.IsEmptyHost(),
		IsEmptyOtp:       WafOtpServiceApp.IsEmptyOtp(tokenInfo.LoginAccount),
	}
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
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteDay{}).
		Where("day = ? and host_code in ?", currentDay, hostCodes).
		Select("host_code, sum(total_count) as total_count, sum(attack_count) as attack_count, sum(traffic_in) as traffic_in, sum(traffic_out) as traffic_out").
		Group("host_code").
		Scan(&siteRows)

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
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
		Where("day = ? and host_code in ?", currentDay, hostCodes).
		Select("host_code, count(distinct ip) as uv_count").
		Group("host_code").
		Scan(&uvRows)

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
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteDay{}).
		Where("day between ? and ?", req.StartDay, req.EndDay).
		Select("host_code, host, sum(total_count) as total_count, sum(attack_count) as attack_count, sum(normal_count) as normal_count, sum(traffic_in) as traffic_in, sum(traffic_out) as traffic_out, sum(total_time_spent) as total_time_spent").
		Group("host_code").
		Scan(&rows)

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
		global.GWAF_LOCAL_DB.Model(&model.Hosts{}).
			Where("code in ?", hostCodes).
			Select("code, remarks").
			Scan(&hostRows)
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
	global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
		Where("day between ? and ?", req.StartDay, req.EndDay).
		Select("host_code, count(distinct ip) as uv_count").
		Group("host_code").
		Scan(&uvRows)
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
		global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteHour{}).
			Where("host_code = ? and hour_time >= ?", req.HostCode, startTs).
			Order("hour_time asc").Scan(&pts)

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
		global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteHour{}).
			Where("host_code = ? and hour_time >= ?", req.HostCode, startTs).
			Order("hour_time asc").Scan(&pts)

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
		global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteDay{}).
			Where("host_code = ? and day between ? and ?", req.HostCode, startDay, endDay).
			Select("day, sum(total_count) as total_count, sum(attack_count) as attack_count, sum(normal_count) as normal_count, sum(total_time_spent) as total_time_spent").
			Group("day").Order("day asc").Scan(&dayRows)
		// UV
		type uvDay struct {
			Day     int
			UvCount int64
		}
		var uvDays []uvDay
		global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
			Where("host_code = ? and day between ? and ?", req.HostCode, startDay, endDay).
			Select("day, count(distinct ip) as uv_count").
			Group("day").Order("day asc").Scan(&uvDays)
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
		global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteDay{}).
			Where("host_code = ? and day between ? and ?", req.HostCode, startDay, endDay).
			Select("day, sum(total_count) as total_count, sum(attack_count) as attack_count, sum(normal_count) as normal_count, sum(total_time_spent) as total_time_spent").
			Group("day").Order("day asc").Scan(&dayRows)
		type uvDay struct {
			Day     int
			UvCount int64
		}
		var uvDays []uvDay
		global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
			Where("host_code = ? and day between ? and ?", req.HostCode, startDay, endDay).
			Select("day, count(distinct ip) as uv_count").
			Group("day").Order("day asc").Scan(&uvDays)
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
		global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteHour{}).
			Where("host_code = ? and hour_time >= ?", req.HostCode, startTs).
			Order("hour_time asc").Scan(&pts)

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
	data = append(data, response2.WafNameValue{Name: "系统类型", Value: fmt.Sprintf("%v", runtime.GOOS)})
	data = append(data, response2.WafNameValue{Name: "系统架构", Value: fmt.Sprintf("%v", runtime.GOARCH)})
	data = append(data, response2.WafNameValue{Name: "编译器版本", Value: fmt.Sprintf("%v", runtime.Version())})
	data = append(data, response2.WafNameValue{Name: "Win7内核", Value: func() string {
		if global.GWAF_RUNTIME_WIN7_VERSION == "true" {
			return "是"
		}
		return "否"
	}()})
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

	data = append(data, response2.WafNameValue{Name: "软件版本", Value: fmt.Sprintf("%v", global.GWAF_RELEASE_VERSION_NAME)})
	data = append(data, response2.WafNameValue{Name: "软件版本Code", Value: fmt.Sprintf("%v", global.GWAF_RELEASE_VERSION)})
	data = append(data, response2.WafNameValue{Name: "当前QPS", Value: fmt.Sprintf("%v", global.GetRealtimeQPS())})

	data = append(data, response2.WafNameValue{Name: "当前队列数", Value: fmt.Sprintf("主数据：%v 日志数据：%v  统计数据：%v  消息队列：%v", global.GQEQUE_DB.Size(), global.GQEQUE_LOG_DB.Size(), global.GQEQUE_STATS_DB.Size(), global.GQEQUE_MESSAGE_DB.Size())})
	data = append(data, response2.WafNameValue{Name: "当前日志队列处理QPS", Value: fmt.Sprintf("%v", global.GetRealtimeLogQPS())})
	data = append(data, response2.WafNameValue{Name: "当前web端口使用列表", Value: fmt.Sprintf("%v", global.GWAF_RUNTIME_CURRENT_WEBPORT)})
	data = append(data, response2.WafNameValue{Name: "当前隧道端口使用列表", Value: fmt.Sprintf("%v", global.GWAF_RUNTIME_CURRENT_TUNNELPORT)})

	return data
}
