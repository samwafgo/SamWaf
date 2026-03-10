package request

// WafStatsSiteOverviewReq 站点综合概览请求（按天范围查询）
type WafStatsSiteOverviewReq struct {
	StartDay string `json:"start_day" form:"start_day"` //开始日期 如 20260301
	EndDay   string `json:"end_day"   form:"end_day"`   //结束日期 如 20260310
}

// WafStatsSiteDetailReq 站点详情趋势请求
type WafStatsSiteDetailReq struct {
	HostCode  string `json:"host_code"  form:"host_code"`  //网站唯一码
	TimeRange string `json:"time_range" form:"time_range"` //时间范围: 1h | 24h | 7d | 30d
}
