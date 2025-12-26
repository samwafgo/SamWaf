package request

import "SamWaf/model/common/request"

type WafRuleAddReq struct {
	RuleCode     string `json:"rule_code"` //规则编号v4
	RuleJson     string `json:"rule_json"`
	IsManualRule int    `json:"is_manual_rule"` // 0 是界面  1是纯代码
	RuleContent  string `json:"rule_content"`   //规则内容
	RuleStatus   int    `json:"rule_status"`    //规则状态 1 是开启 0 是关闭
}
type WafRuleDelReq struct {
	CODE string `json:"code"`
}
type WafRuleDetailReq struct {
	CODE string `json:"code"`
}
type WafRuleEditReq struct {
	CODE         string `json:"code"`
	RuleJson     string `json:"rule_json"`
	IsManualRule int    `json:"is_manual_rule"`
	RuleContent  string `json:"rule_content"` //规则内容
	RuleStatus   int    `json:"rule_status"`  //规则状态 1 是开启 0 是关闭
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
type WafRulePreViewReq struct {
	RuleCode     string `json:"rule_code"`      //规则编号v4
	RuleJson     string `json:"rule_json"`      //规则json字符串
	IsManualRule int    `json:"is_manual_rule"` // 0 是界面  1是纯代码
	RuleContent  string `json:"rule_content"`   //规则内容
	FormSource   string `json:"form_source"`    //来源是 builder ？ 不校验 选择的站点
}

type WafRuleStatusReq struct {
	CODE        string `json:"code"`
	RULE_STATUS int    `json:"rule_status" form:"rule_status"` //规则状态 1 是开启 0 是关闭
}
