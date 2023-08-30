package request

import "SamWaf/model/common/request"

type WafAttackLogSearch struct {
	HostCode   string `json:"host_code" form:"host_code"`     //主机码
	Rule       string `json:"rule" form:"rule"`               //规则名
	Action     string `json:"action" form:"action"`           //状态
	SrcIp      string `json:"src_ip" form:"src_ip"`           //请求IP
	StatusCode string `json:"status_code" form:"status_code"` //响应码
	request.PageInfo
}
