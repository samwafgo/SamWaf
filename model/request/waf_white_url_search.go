package request

import "SamWaf/model/common/request"

type WafWhiteUrlSearchReq struct {
	HostCode string `json:"host_code" ` //主机码
	Url      string `json:"url"`        //白名单url
	request.PageInfo
}
