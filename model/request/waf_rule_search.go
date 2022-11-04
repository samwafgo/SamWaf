package request

import "SamWaf/model/common/request"

type WafRuleSearchReq struct {
	HostCode string `json:"host_code" form:"host_code"` //主机码
	request.PageInfo
}
