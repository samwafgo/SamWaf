package request

/*
*
获取国家维度的访问或者攻击数
*/
type WafStatsAnalysisDayRangeCountryReq struct {
	StartDay   string `json:"start_day"  form:"start_day"`
	EndDay     string `json:"end_day"  form:"end_day"`
	AttackType string `json:"attack_type"  form:"attack_type"`
}
