package response

// WafAnalysisSpiderResp 爬虫分析数据值
type WafAnalysisSpiderResp struct {
	Name  string `json:"name"  form:"name"`
	Value int64  `json:"value"  form:"value"`
}
