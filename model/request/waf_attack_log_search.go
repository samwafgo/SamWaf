package request

import "SamWaf/model/common/request"

type WafAttackLogSearch struct {
	HostCode         string `json:"host_code" form:"host_code"`                     //主机码
	Rule             string `json:"rule" form:"rule"`                               //规则名
	Action           string `json:"action" form:"action"`                           //状态
	SrcIp            string `json:"src_ip" form:"src_ip"`                           //请求IP
	StatusCode       string `json:"status_code" form:"status_code"`                 //响应码
	UnixAddTimeBegin string `json:"unix_add_time_begin" form:"unix_add_time_begin"` //开始时间
	UnixAddTimeEnd   string `json:"unix_add_time_end" form:"unix_add_time_end"`     //结束时间
	Method           string `json:"method" form:"method"`                           //访问方法
	request.PageInfo
}
