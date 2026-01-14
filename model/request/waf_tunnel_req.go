package request

import "SamWaf/model/common/request"

type WafTunnelAddReq struct {
	Code              string `json:"code" form:"code"`
	Name              string `json:"name" form:"name"`
	Port              string `json:"port" form:"port"`
	Protocol          string `json:"protocol" form:"protocol"`
	RemotePort        int    `json:"remote_port" form:"remote_port"`
	RemoteIp          string `json:"remote_ip" form:"remote_ip"`
	AllowIp           string `json:"allow_ip" form:"allow_ip"`
	DenyIp            string `json:"deny_ip" form:"deny_ip"`
	StartStatus       int    `json:"start_status" form:"start_status"`
	ConnTimeout       int    `json:"conn_timeout" form:"conn_timeout"`
	ReadTimeout       int    `json:"read_timeout" form:"read_timeout"`
	WriteTimeout      int    `json:"write_timeout" form:"write_timeout"`
	MaxInConnect      int    `json:"max_in_connect" form:"max_in_connect"`
	MaxOutConnect     int    `json:"max_out_connect" form:"max_out_connect"`
	AllowedTimeRanges string `json:"allowed_time_ranges" form:"allowed_time_ranges"`
	IpVersion         string `json:"ip_version" form:"ip_version"`
	Remark            string `json:"remark" form:"remark"`
}
type WafTunnelEditReq struct {
	Id string `json:"id"`

	Code              string `json:"code" form:"code"`
	Name              string `json:"name" form:"name"`
	Port              string `json:"port" form:"port"`
	Protocol          string `json:"protocol" form:"protocol"`
	RemotePort        int    `json:"remote_port" form:"remote_port"`
	RemoteIp          string `json:"remote_ip" form:"remote_ip"`
	AllowIp           string `json:"allow_ip" form:"allow_ip"`
	DenyIp            string `json:"deny_ip" form:"deny_ip"`
	StartStatus       int    `json:"start_status" form:"start_status"`
	ConnTimeout       int    `json:"conn_timeout" form:"conn_timeout"`
	ReadTimeout       int    `json:"read_timeout" form:"read_timeout"`
	WriteTimeout      int    `json:"write_timeout" form:"write_timeout"`
	MaxInConnect      int    `json:"max_in_connect" form:"max_in_connect"`
	MaxOutConnect     int    `json:"max_out_connect" form:"max_out_connect"`
	AllowedTimeRanges string `json:"allowed_time_ranges" form:"allowed_time_ranges"`
	IpVersion         string `json:"ip_version" form:"ip_version"`
	Remark            string `json:"remark" form:"remark"`
}
type WafTunnelDetailReq struct {
	Id string `json:"id"   form:"id"`
}
type WafTunnelDelReq struct {
	Id string `json:"id"   form:"id"`
}
type WafTunnelSearchReq struct {
	request.PageInfo
}

// WafTunnelConnReq 通过ID获取隧道连接请求
type WafTunnelConnReq struct {
	ID string `json:"id" form:"id"`
}
