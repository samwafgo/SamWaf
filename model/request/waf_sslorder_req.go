package request

import "SamWaf/model/common/request"

type WafSslorderaddReq struct {
	HostCode      string `json:"host_code"`      //网站唯一码（主要键）
	ApplyPlatform string `json:"apply_platform"` //申请平台
	ApplyMethod   string `json:"apply_method"`   //申请方式http，dns
	ApplyDns      string `json:"apply_dns"`      //申请dns服务商
	ApplyEmail    string `json:"apply_email"`    //申请邮箱
	ApplyDomain   string `json:"apply_domain"`   //申请域名
}
type WafSslordereditReq struct {
	Id            string `json:"id"`
	HostCode      string `json:"host_code"`      //网站唯一码（主要键）
	ApplyPlatform string `json:"apply_platform"` //申请平台
	ApplyMethod   string `json:"apply_method"`   //申请方式http01，dns
	ApplyDns      string `json:"apply_dns"`      //申请dns服务商
	ApplyEmail    string `json:"apply_email"`    //申请邮箱
	ApplyDomain   string `json:"apply_domain"`   //申请域名
	ApplyStatus   string `json:"apply_status"`   //申请状态
}
type WafSslorderdetailReq struct {
	Id string `json:"id"   form:"id"`
}
type WafSslorderdeleteReq struct {
	Id string `json:"id"   form:"id"`
}
type WafSslordersearchReq struct {
	ApplyDomain string `json:"apply_domain"` //申请域名
	HostCode    string `json:"host_code"`    //网站唯一码（主要键）
	request.PageInfo
}
