package request

import "SamWaf/model/common/request"

type WafBlockIpAddReq struct {
	HostCode    string `json:"host_code" binding:"required"` //网站唯一码（主要键）
	Ip          string `json:"ip" binding:"required"`        //Block ip
	Remarks     string `json:"remarks"`                      //备注
	TargetLayer string `json:"target_layer"`                 //封禁层级: ""/waf(WAF应用层) | system(系统防火墙) | both(两者)
}

type WafBlockIpEditReq struct {
	Id       string `json:"id" binding:"required"`        //Block IP唯一键
	HostCode string `json:"host_code" binding:"required"` //网站唯一码（主要键）
	Ip       string `json:"ip" binding:"required"`        //Block ip
	Remarks  string `json:"remarks"`                      //备注
}
type WafBlockIpDelReq struct {
	Id string `json:"id"  form:"id"` //Block IP唯一键
}

type WafBlockIpSearchReq struct {
	HostCode string `json:"host_code" ` //主机码
	Ip       string `json:"ip"`         //Block ip
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
