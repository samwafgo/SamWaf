package request

type WafRuleAddReq struct {
	RuleCode     string `json:"rule_code"` //规则编号v4
	RuleJson     string
	IsManualRule int    `json:"is_manual_rule"`
	RuleContent  string `json:"rule_content"` //规则内容
}
