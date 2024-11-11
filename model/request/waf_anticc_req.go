package request

import "SamWaf/model/common/request"

type WafAntiCCAddReq struct {
	HostCode      string `json:"host_code"  form:"host_code"` //网站唯一码（主要键）
	Url           string `json:"url" form:"url"`              //白名单url
	Rate          int    `json:"rate"  form:"rate"`           //速率
	Limit         int    `json:"limit" form:"limit"`          //限制
	LockIPMinutes int    `json:"lock_minutes"`                //封禁分钟
	Remarks       string `json:"remarks" form:"remarks"`      //备注
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
	Id            string `json:"id"`                          //白名单url唯一键
	HostCode      string `json:"host_code"  form:"host_code"` //网站唯一码（主要键）
	Url           string `json:"url" form:"url"`              //白名单url
	Rate          int    `json:"rate"  form:"rate"`           //速率
	Limit         int    `json:"limit" form:"limit"`          //限制
	LockIPMinutes int    `json:"lock_minutes"`                //封禁分钟
	Remarks       string `json:"remarks" form:"remarks"`      //备注
}

// WafAntiCCRemoveBanIpReq 移除封禁ip
type WafAntiCCRemoveBanIpReq struct {
	Ip string `json:"ip"  form:"ip"` //移除封禁ip
}
