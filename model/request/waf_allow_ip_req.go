package request

import "SamWaf/model/common/request"

// Ip 字段去掉了 binding:"required"：条目类型为 group 时不填 Ip。
// 必填校验改为按 IpType 在 api 层做（见 api/waf_ip_entry_validate.go）。
type WafAllowIpAddReq struct {
	HostCode  string `json:"host_code" binding:"required"` //网站唯一码（主要键）
	Ip        string `json:"ip"`                           //白名单ip：单IP / CIDR / 通配符(10.10.*.*) / 区间(起-止)
	Remarks   string `json:"remarks"`                      //备注
	IpType    string `json:"ip_type"`                      //条目类型: ""/ip(单条) | group(引用IP组)
	GroupCode string `json:"group_code"`                   //IpType=group 时的IP组短码
	IsEnable  *int   `json:"is_enable"`                    //启用状态：nil=新增默认启用/编辑不改动，0停用 1启用
}
type WafAllowIpDelReq struct {
	Id string `json:"id"  form:"id"` //白名单IP唯一键
}
type WafAllowIpDetailReq struct {
	Id string `json:"id"  form:"id"` //白名单IP唯一键
}

type WafAllowIpEditReq struct {
	Id        string `json:"id" binding:"required"`        //白名单IP唯一键
	HostCode  string `json:"host_code" binding:"required"` //网站唯一码（主要键）
	Ip        string `json:"ip"`                           //白名单ip：单IP / CIDR / 通配符 / 区间
	Remarks   string `json:"remarks"`                      //备注
	IpType    string `json:"ip_type"`                      //条目类型: ""/ip(单条) | group(引用IP组)
	GroupCode string `json:"group_code"`                   //IpType=group 时的IP组短码
	IsEnable  *int   `json:"is_enable"`                    //启用状态：nil=新增默认启用/编辑不改动，0停用 1启用
}
type WafAllowIpSearchReq struct {
	HostCode  string `json:"host_code" ` //主机码
	Ip        string `json:"ip"`         //白名单ip
	GroupCode string `json:"group_code"` //按引用的IP组筛选（Ip 是精确匹配，对组引用行永远查不到）
	request.PageInfo
}
type WafAllowIpBatchDelReq struct {
	Ids []string `json:"ids" binding:"required"` //白名单IP唯一键数组
}

type WafAllowIpDelAllReq struct {
	HostCode string `json:"host_code" form:"host_code"` //网站唯一码，为空则删除所有
}

type WafAllowIpToggleReq struct {
	Id       string `json:"id" form:"id" binding:"required"`               //条目唯一键
	IsEnable *int   `json:"is_enable" form:"is_enable" binding:"required"` //1启用 0停用（必填，防漏字段被当成停用）
}
