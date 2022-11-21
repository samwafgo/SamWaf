package request

import "SamWaf/model/common/request"

type WafAntiCCSearchReq struct {
	HostCode string `json:"host_code" ` //主机码
	Url      string `json:"url"`        //防护url
	request.PageInfo
}
