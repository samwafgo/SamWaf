package request

type WafRuleAddReq struct {
	RuleJson     string
	IsManualRule int    `json:"is_manual_rule"`
	RuleContent  string `json:"rule_content"` //规则内容
}
