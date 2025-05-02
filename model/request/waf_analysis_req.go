package request

// 爬虫日志分析
type WafAnalysisSpiderReq struct {
	StartDay string `json:"start_day"  form:"start_day"`
	EndDay   string `json:"end_day"  form:"end_day"`
	Host     string `json:"host"  form:"host"`
}
