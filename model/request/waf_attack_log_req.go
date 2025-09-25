package request

import "SamWaf/model/common/request"

type WafAttackLogDetailReq struct {
	CurrrentDbName string `json:"current_db_name"`
	REQ_UUID       string `json:"req_uuid"`
	OutputFormat   string `json:"output_format"` //输出格式 raw,curl
}

type WafAttackLogDoExport struct {
	CurrrentDbName string `json:"current_db_name"`
	HostCode       string `json:"host_code" form:"host_code"` //主机码
}
type WafAttackLogSearch struct {
	CurrrentDbName   string `json:"current_db_name"`
	HostCode         string `json:"host_code" form:"host_code"`                     //主机码
	Rule             string `json:"rule" form:"rule"`                               //规则名
	ReqUuid          string `json:"req_uuid" form:"req_uuid"`                       //请求UUID
	Action           string `json:"action" form:"action"`                           //状态
	SrcIp            string `json:"src_ip" form:"src_ip"`                           //请求IP
	StatusCode       string `json:"status_code" form:"status_code"`                 //响应码
	UnixAddTimeBegin string `json:"unix_add_time_begin" form:"unix_add_time_begin"` //开始时间
	UnixAddTimeEnd   string `json:"unix_add_time_end" form:"unix_add_time_end"`     //结束时间
	Method           string `json:"method" form:"method"`                           //访问方法
	LogOnlyMode      string `json:"log_only_mode" form:"log_only_mode"`             //日志模式
	SortBy           string `json:"sort_by" form:"sort_by"`                         //排序字段
	SortDescending   string `json:"sort_descending" form:"sort_descending"`         //排序方式
	FilterBy         string `json:"filter_by" form:"filter_by"`                     //筛选字段
	FilterValue      string `json:"filter_value" form:"filter_value"`               //筛选值
	request.PageInfo
}

type WafAttackIpTagSearch struct {
	Rule  string `json:"rule" form:"rule"`     //规则名
	SrcIp string `json:"src_ip" form:"src_ip"` //请求IP
	request.PageInfo
}
