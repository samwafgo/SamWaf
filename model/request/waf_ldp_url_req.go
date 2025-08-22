package request

import "SamWaf/model/common/request"

type WafLdpUrlAddReq struct {
	HostCode    string `json:"host_code"`    //网站唯一码（主要键）
	CompareType string `json:"compare_type"` //对比方式
	Url         string `json:"url"`          //加隐私保护的url
	Remarks     string `json:"remarks"`      //备注
}
type WafLdpUrlDelReq struct {
	Id string `json:"id"  form:"id"` //隐私保护url唯一键
}
type WafLdpUrlDetailReq struct {
	Id string `json:"id"  form:"id"` //隐私保护Url唯一键
}
type WafLdpUrlEditReq struct {
	Id          string `json:"id"`           //隐私保护url唯一键
	HostCode    string `json:"host_code"`    //网站唯一码（主要键）
	CompareType string `json:"compare_type"` //对比方式
	Url         string `json:"url"`          //隐私保护url
	Remarks     string `json:"remarks"`      //备注
}
type WafLdpUrlSearchReq struct {
	HostCode string `json:"host_code" ` //主机码
	Url      string `json:"url"`        //隐私保护url
	request.PageInfo
}
type WafLdpUrlBatchDelReq struct {
	Ids []string `json:"ids" binding:"required"` //隐私保护URL唯一键数组
}

type WafLdpUrlDelAllReq struct {
	HostCode string `json:"host_code" form:"host_code"` //网站唯一码，为空则删除所有
}
