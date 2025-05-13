package request

import "SamWaf/model/common/request"

type WafCacheRuleAddReq struct {
	HostCode      string `json:"host_code" gorm:"column:host_code" form:"host_code" gorm:"column:host_code"`
	RuleName      string `json:"rule_name" gorm:"column:rule_name" form:"rule_name" gorm:"column:rule_name"`
	RuleType      int    `json:"rule_type" gorm:"column:rule_type" form:"rule_type" gorm:"column:rule_type"`
	RuleContent   string `json:"rule_content" gorm:"column:rule_content" form:"rule_content" gorm:"column:rule_content"`
	ParamType     int    `json:"param_type" gorm:"column:param_type" form:"param_type" gorm:"column:param_type"`
	CacheTime     int    `json:"cache_time" gorm:"column:cache_time" form:"cache_time" gorm:"column:cache_time"`
	Priority      int    `json:"priority" gorm:"column:priority" form:"priority" gorm:"column:priority"`
	RequestMethod string `json:"request_method" gorm:"column:request_method" form:"request_method" gorm:"column:request_method"`
	Remarks       string `json:"remarks" gorm:"column:remarks" form:"remarks" gorm:"column:remarks"`
}
type WafCacheRuleEditReq struct {
	Id            string `json:"id"`
	HostCode      string `json:"host_code" gorm:"column:host_code" form:"host_code" gorm:"column:host_code"`
	RuleName      string `json:"rule_name" gorm:"column:rule_name" form:"rule_name" gorm:"column:rule_name"`
	RuleType      int    `json:"rule_type" gorm:"column:rule_type" form:"rule_type" gorm:"column:rule_type"`
	RuleContent   string `json:"rule_content" gorm:"column:rule_content" form:"rule_content" gorm:"column:rule_content"`
	ParamType     int    `json:"param_type" gorm:"column:param_type" form:"param_type" gorm:"column:param_type"`
	CacheTime     int    `json:"cache_time" gorm:"column:cache_time" form:"cache_time" gorm:"column:cache_time"`
	Priority      int    `json:"priority" gorm:"column:priority" form:"priority" gorm:"column:priority"`
	RequestMethod string `json:"request_method" gorm:"column:request_method" form:"request_method" gorm:"column:request_method"`
	Remarks       string `json:"remarks" gorm:"column:remarks" form:"remarks" gorm:"column:remarks"`
}
type WafCacheRuleDetailReq struct {
	Id string `json:"id"   form:"id"`
}
type WafCacheRuleDelReq struct {
	Id string `json:"id"   form:"id"`
}
type WafCacheRuleSearchReq struct {
	HostCode string `json:"host_code" gorm:"column:host_code" form:"host_code" gorm:"column:host_code"`
	request.PageInfo
}
