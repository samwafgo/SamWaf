package request

import "SamWaf/model/common/request"

type WafRuleSearchReq struct {
	HostCode string `json:"host_code" form:"host_code"` //主机码
	RuleName string `json:"rule_name" form:"rule_name"` //规则名
	request.PageInfo
}
