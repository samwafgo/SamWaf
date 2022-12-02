package request

type WafStatsDayRangeReq struct {
	StartDay string `json:"start_day"  form:"start_day"`
	EndDay   string `json:"end_day"  form:"end_day"`
}
