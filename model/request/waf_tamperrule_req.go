package request

import "SamWaf/model/common/request"

type WafTamperRuleAddReq struct {
	HostCode    string `json:"host_code" form:"host_code"`
	Url         string `json:"url" form:"url"`
	RuleName    string `json:"rule_name" form:"rule_name"`
	IsEnable    int    `json:"is_enable" form:"is_enable"`
	IgnoreQuery int    `json:"ignore_query" form:"ignore_query"`
	Remarks     string `json:"remarks" form:"remarks"`
}
type WafTamperRuleEditReq struct {
	Id          string `json:"id"`
	HostCode    string `json:"host_code" form:"host_code"`
	Url         string `json:"url" form:"url"`
	RuleName    string `json:"rule_name" form:"rule_name"`
	IsEnable    int    `json:"is_enable" form:"is_enable"`
	IgnoreQuery int    `json:"ignore_query" form:"ignore_query"`
	Remarks     string `json:"remarks" form:"remarks"`
}
type WafTamperRuleDetailReq struct {
	Id string `json:"id" form:"id"`
}
type WafTamperRuleDelReq struct {
	Id string `json:"id" form:"id"`
}
type WafTamperRuleRelearnReq struct {
	Id string `json:"id" form:"id"`
}

// WafTamperRuleBaselineReq 查看/下载基线正文
type WafTamperRuleBaselineReq struct {
	Id string `json:"id" form:"id"`
}
type WafTamperRuleSearchReq struct {
	HostCode string `json:"host_code" form:"host_code"`
	request.PageInfo
}
