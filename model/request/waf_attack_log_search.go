package request

import "SamWaf/model/common/request"

type WafAttackLogSearch struct {
	HostCode string `json:"host_code" form:"host_code"` //主机码
	request.PageInfo
}
