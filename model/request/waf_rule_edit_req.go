package request

type WafRuleEditReq struct {
	CODE     string `json:"code"`
	RuleJson string `json:"rulejson"`
}
