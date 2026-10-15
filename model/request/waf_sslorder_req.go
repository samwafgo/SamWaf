package request

import "SamWaf/model/common/request"

type WafSslorderaddReq struct {
	HostCode         string `json:"host_code"`                         //网站唯一码（主要键）
	ApplyPlatform    string `json:"apply_platform"`                    //申请平台，取CA服务器名称（ca_server_name），默认 letsencrypt
	ApplyMethod      string `json:"apply_method" enums:"http01,dns01"` //申请方式：http01(HTTP 文件验证) 或 dns01(DNS 验证)
	SkipDNSVerify    int64  `json:"skip_dns_verify"`                   //dns01是否跳过本地DNS传播校验 0否 1是
	ApplyDns         string `json:"apply_dns"`                         //申请dns服务商
	ApplyEmail       string `json:"apply_email"`                       //申请邮箱
	ApplyDomain      string `json:"apply_domain"`                      //申请域名
	PrivateGroupName string `json:"private_group_name"`                //密钥分组名称DNS有效
}
type WafSslordereditReq struct {
	Id               string `json:"id"`
	HostCode         string `json:"host_code"`                         //网站唯一码（主要键）
	ApplyPlatform    string `json:"apply_platform"`                    //申请平台，取CA服务器名称（ca_server_name），默认 letsencrypt
	ApplyMethod      string `json:"apply_method" enums:"http01,dns01"` //申请方式：http01(HTTP 文件验证) 或 dns01(DNS 验证)
	SkipDNSVerify    int64  `json:"skip_dns_verify"`                   //dns01是否跳过本地DNS传播校验 0否 1是
	ApplyDns         string `json:"apply_dns"`                         //申请dns服务商
	ApplyEmail       string `json:"apply_email"`                       //申请邮箱
	ApplyDomain      string `json:"apply_domain"`                      //申请域名
	ApplyStatus      string `json:"apply_status"`                      //申请状态
	PrivateGroupName string `json:"private_group_name"`                //密钥分组名称DNS有效
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
