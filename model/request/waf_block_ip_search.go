package request

import "SamWaf/model/common/request"

type WafBlockIpSearchReq struct {
	HostCode string `json:"host_code" ` //主机码
	Ip       string `json:"ip"`         //Block ip
	request.PageInfo
}
