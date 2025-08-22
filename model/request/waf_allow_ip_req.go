package request

import "SamWaf/model/common/request"

type WafAllowIpAddReq struct {
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Ip       string `json:"ip"`        //白名单ip
	Remarks  string `json:"remarks"`   //备注
}
type WafAllowIpDelReq struct {
	Id string `json:"id"  form:"id"` //白名单IP唯一键
}
type WafAllowIpDetailReq struct {
	Id string `json:"id"  form:"id"` //白名单IP唯一键
}

type WafAllowIpEditReq struct {
	Id       string `json:"id"`        //白名单IP唯一键
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Ip       string `json:"ip"`        //白名单ip
	Remarks  string `json:"remarks"`   //备注
}
type WafAllowIpSearchReq struct {
	HostCode string `json:"host_code" ` //主机码
	Ip       string `json:"ip"`         //白名单ip
	request.PageInfo
}
type WafAllowIpBatchDelReq struct {
	Ids []string `json:"ids" binding:"required"` //白名单IP唯一键数组
}

type WafAllowIpDelAllReq struct {
	HostCode string `json:"host_code" form:"host_code"` //网站唯一码，为空则删除所有
}
