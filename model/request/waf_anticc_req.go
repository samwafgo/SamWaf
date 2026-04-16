package request

import "SamWaf/model/common/request"

type WafAntiCCAddReq struct {
	HostCode      string `json:"host_code"  form:"host_code" binding:"required"`            //网站唯一码（主要键）
	Url           string `json:"url" form:"url" binding:"required"`                         //白名单url
	Rate          int    `json:"rate"  form:"rate" binding:"required"`                      //速率
	Limit         int    `json:"limit" form:"limit" binding:"required"`                     //限制
	LockIPMinutes int    `json:"lock_ip_minutes" form:"lock_ip_minutes" binding:"required"` //封禁分钟
	LimitMode     string `json:"limit_mode"  form:"limit_mode" binding:"required"`          // "rate" 或 "window"
	IsEnableRule  bool   `json:"is_enable_rule" form:"is_enable_rule" binding:"required"`   //是否启动规则
	RuleContent   string `json:"rule_content" form:"rule_content"`                          //规则内容
	Remarks       string `json:"remarks" form:"remarks"`                                    //备注
}
type WafAntiCCSearchReq struct {
	HostCode string `json:"host_code" ` //主机码
	request.PageInfo
}
type WafAntiCCDelReq struct {
	Id string `json:"id"  form:"id"` //白名单url唯一键
}
type WafAntiCCDetailReq struct {
	Id string `json:"id"  form:"id"` //白名单Url唯一键
}
type WafAntiCCEditReq struct {
	Id            string `json:"id" binding:"required"`                                      //白名单url唯一键
	HostCode      string `json:"host_code"  form:"host_code" binding:"required"`             //网站唯一码（主要键）
	Url           string `json:"url" form:"url" binding:"required"`                          //白名单url
	Rate          int    `json:"rate"  form:"rate" binding:"required"`                       //速率
	Limit         int    `json:"limit" form:"limit" binding:"required"`                      //限制
	LockIPMinutes int    `json:"lock_ip_minutes"  form:"lock_ip_minutes" binding:"required"` //封禁分钟
	LimitMode     string `json:"limit_mode"  form:"limit_mode" binding:"required"`           // "rate" 或 "window"
	IsEnableRule  bool   `json:"is_enable_rule" form:"is_enable_rule" binding:"required"`    //是否启动规则
	RuleContent   string `json:"rule_content" form:"rule_content"`                           //规则内容
	Remarks       string `json:"remarks" form:"remarks"`                                     //备注
}

// WafAntiCCRemoveBanIpReq 移除封禁ip
type WafAntiCCRemoveBanIpReq struct {
	Ip string `json:"ip"  form:"ip"` //移除封禁ip
}
