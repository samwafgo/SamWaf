package request

import "SamWaf/model/common/request"

type WafAllowIpSearchReq struct {
	HostCode string `json:"host_code" ` //主机码
	Ip       string `json:"ip"`         //白名单ip
	request.PageInfo
}
