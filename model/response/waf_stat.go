package response

import "SamWaf/model"

type WafStat struct {
	AttackCountOfToday          int64  //今日攻击数量
	VisitCountOfToday           int64  //今天访问数量
	AttackCountOfYesterday      int64  //昨日攻击数量
	VisitCountOfYesterday       int64  //昨日访问数量
	AttackCountOfLastWeekToday  int64  //上周攻击数量
	VisitCountOfLastWeekToday   int64  //上周访问数量
	NormalIpCountOfToday        int64  //今日正常IP数量
	IllegalIpCountOfToday       int64  //今日非法IP数量
	NormalCountryCountOfToday   int64  //今日正常国家数量
	IllegalCountryCountOfToday  int64  //今日非法国家数量
	NormalProvinceCountOfToday  int64  //今日正常省份数量
	IllegalProvinceCountOfToday int64  //今日非法省份数量
	NormalCityCountOfToday      int64  //今日正常城市数量
	IllegalCityCountOfToday     int64  //今日非法城市数量
	CurrentQps                  uint64 //当前QPS
}
type WafStatRange struct {
	AttackCountOfRange map[int]int64 //区间攻击数量
	NormalCountOfRange map[int]int64 //区间正常数量
}
type WafCityStats struct {
	AttackCityOfRange map[string]int64 //区间攻击城市数量
	NormalCityOfRange map[string]int64 //区间正常城市数量
}
type WafIPStats struct {
	AttackIPOfRange []model.StatsIPCountMore //区间攻击IP数量
	NormalIPOfRange []model.StatsIPCountMore //区间正常IP数量
}

/*
*
数据分析：返回国家和对应的访问数量 或者攻击数量
*/
type WafAnalysisDayStats struct {
	Name  string `json:"name"  form:"name"`
	Value int64  `json:"value"  form:"value"`
}

/*
*
首页 获取系统基本信息
*/
type WafHomeSysinfoStat struct {
	IsDefaultAccount bool `json:"is_default_account"  form:"is_default_account"`
	IsEmptyHost      bool `json:"is_empty_host"  form:"is_empty_host"`
	IsEmptyOtp       bool `json:"is_empty_otp"  form:"is_empty_otp"`
}
type WafNameValue struct {
	Name  string `json:"name"  form:"name"`
	Value string `json:"value"  form:"value"`
}

/*
*
站点综合概览响应（顶部汇总卡片 + 站点明细列表）
*/
type WafSiteOverview struct {
	TotalIp     int64               `json:"total_ip"`     //汇总：独立IP数
	TotalUv     int64               `json:"total_uv"`     //汇总：独立访客UV
	TotalPv     int64               `json:"total_pv"`     //汇总：总PV(请求数)
	TotalAttack int64               `json:"total_attack"` //汇总：总攻击拦截
	TotalInMb   float64             `json:"total_in_mb"`  //汇总：入站流量MB
	TotalOutMb  float64             `json:"total_out_mb"` //汇总：出站流量MB
	SiteList    []WafSiteStatDetail `json:"site_list"`    //各站点明细
}

/*
*
单站点统计明细
*/
type WafSiteStatDetail struct {
	HostCode     string  `json:"host_code"`
	Host         string  `json:"host"`
	HostRemark   string  `json:"host_remark"`
	TotalCount   int64   `json:"total_count"`
	AttackCount  int64   `json:"attack_count"`
	NormalCount  int64   `json:"normal_count"`
	TrafficInMb  float64 `json:"traffic_in_mb"`
	TrafficOutMb float64 `json:"traffic_out_mb"`
	UvCount      int64   `json:"uv_count"`
	IpCount      int64   `json:"ip_count"`
	AvgTimeMs    float64 `json:"avg_time_ms"`
}

/*
*
站点详情趋势响应（用于弹窗图表）
*/
type WafSiteDetail struct {
	HostCode          string             `json:"host_code"`
	Host              string             `json:"host"`
	AvgTimeMs         float64            `json:"avg_time_ms"`         //平均响应时间(ms)
	NormalRatePercent float64            `json:"normal_rate_percent"` //正常流量占比(%)
	HourTrend         []WafSiteHourPoint `json:"hour_trend"`          //小时级趋势(1h/24h模式)
	DayTrend          []WafSiteDayPoint  `json:"day_trend"`           //天级趋势(7d/30d模式)
	// 内部计算用（不暴露给前端）
	TotalTimeSpentSum int64 `json:"-"`
	TotalCountSum     int64 `json:"-"`
}

/*
*
小时级趋势点
*/
type WafSiteHourPoint struct {
	HourTime    int64 `json:"hour_time"` //整点unix时间戳(秒)
	TotalCount  int64 `json:"total_count"`
	AttackCount int64 `json:"attack_count"`
	NormalCount int64 `json:"normal_count"`
}

/*
*
天级趋势点
*/
type WafSiteDayPoint struct {
	Day         int   `json:"day"` //年月日 20260310
	TotalCount  int64 `json:"total_count"`
	AttackCount int64 `json:"attack_count"`
	NormalCount int64 `json:"normal_count"`
	UvCount     int64 `json:"uv_count"`
}
