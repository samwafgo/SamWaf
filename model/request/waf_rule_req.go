package request

import "SamWaf/model/common/request"

type WafRuleAddReq struct {
	RuleCode     string `json:"rule_code"` //规则编号v4
	RuleJson     string
	IsManualRule int    `json:"is_manual_rule"`
	RuleContent  string `json:"rule_content"` //规则内容
}
type WafRuleDelReq struct {
	CODE string `json:"code"`
}
type WafRuleDetailReq struct {
	CODE string `json:"code"`
}
type WafRuleEditReq struct {
	CODE         string `json:"code"`
	RuleJson     string `json:"rulejson"`
	IsManualRule int    `json:"is_manual_rule"`
	RuleContent  string `json:"rule_content"` //规则内容
}
type WafRuleSearchReq struct {
	HostCode string `json:"host_code" form:"host_code"` //主机码
	RuleName string `json:"rule_name" form:"rule_name"` //规则名
	request.PageInfo
}
type WafRuleBatchDelReq struct {
	Codes []string `json:"codes" binding:"required"` //规则编码数组
}

type WafRuleDelAllReq struct {
	HostCode string `json:"host_code" form:"host_code"` //网站唯一码，为空则删除所有
}
