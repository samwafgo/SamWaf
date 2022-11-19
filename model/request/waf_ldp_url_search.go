package request

import "SamWaf/model/common/request"

type WafLdpUrlSearchReq struct {
	HostCode string `json:"host_code" ` //主机码
	Url      string `json:"url"`        //隐私保护url
	request.PageInfo
}
