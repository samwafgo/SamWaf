package request

type WafRuleEditReq struct {
	CODE         string `json:"code"`
	RuleJson     string `json:"rulejson"`
	IsManualRule int    `json:"is_manual_rule"`
	RuleContent  string `json:"rule_content"` //规则内容
}
