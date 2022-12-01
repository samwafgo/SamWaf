package request

import "SamWaf/model/common/request"

type WafBlockUrlSearchReq struct {
	HostCode string `json:"host_code" ` //主机码
	Url      string `json:"url"`        //Block url
	request.PageInfo
}
