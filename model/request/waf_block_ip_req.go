package request

import "SamWaf/model/common/request"

// Ip 字段去掉了 binding:"required"：条目类型为 group 时不填 Ip。
// 必填校验改为按 IpType 在 api 层做（见 api/waf_ip_entry_validate.go），
// 否则老前端漏传 ip 会静默存下一条空行。
type WafBlockIpAddReq struct {
	HostCode    string `json:"host_code" binding:"required"` //网站唯一码（主要键）
	Ip          string `json:"ip"`                           //Block ip：单IP / CIDR / 通配符(10.10.*.*) / 区间(起-止)
	Remarks     string `json:"remarks"`                      //备注
	TargetLayer string `json:"target_layer"`                 //封禁层级: ""/waf(WAF应用层) | system(系统防火墙) | both(两者)
	IpType      string `json:"ip_type"`                      //条目类型: ""/ip(单条) | group(引用IP组)
	GroupCode   string `json:"group_code"`                   //IpType=group 时的IP组短码
}

type WafBlockIpEditReq struct {
	Id        string `json:"id" binding:"required"`        //Block IP唯一键
	HostCode  string `json:"host_code" binding:"required"` //网站唯一码（主要键）
	Ip        string `json:"ip"`                           //Block ip：单IP / CIDR / 通配符 / 区间
	Remarks   string `json:"remarks"`                      //备注
	IpType    string `json:"ip_type"`                      //条目类型: ""/ip(单条) | group(引用IP组)
	GroupCode string `json:"group_code"`                   //IpType=group 时的IP组短码
}
type WafBlockIpDelReq struct {
	Id string `json:"id"  form:"id"` //Block IP唯一键
}

type WafBlockIpSearchReq struct {
	HostCode  string `json:"host_code" ` //主机码
	Ip        string `json:"ip"`         //Block ip
	GroupCode string `json:"group_code"` //按引用的IP组筛选（Ip 是精确匹配，对组引用行永远查不到）
	request.PageInfo
}

type WafBlockIpDetailReq struct {
	Id string `json:"id"  form:"id"` //Block IP唯一键
}

type WafBlockIpBatchDelReq struct {
	Ids []string `json:"ids" binding:"required"` //Block IP唯一键数组
}

type WafBlockIpDelAllReq struct {
	HostCode string `json:"host_code" form:"host_code"` //网站唯一码，为空则删除所有
}
