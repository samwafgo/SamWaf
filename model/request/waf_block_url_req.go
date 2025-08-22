package request

import "SamWaf/model/common/request"

type WafBlockUrlAddReq struct {
	HostCode    string `json:"host_code"`                        //网站唯一码（主要键）
	CompareType string `json:"compare_type" form:"compare_type"` //对比方式
	Url         string `json:"url"`                              //Block url
	Remarks     string `json:"remarks"`                          //备注
}
type WafBlockUrlSearchReq struct {
	HostCode string `json:"host_code" ` //主机码
	Url      string `json:"url"`        //Block url
	request.PageInfo
}

type WafBlockUrlDelReq struct {
	Id string `json:"id"  form:"id"` //Block url唯一键
}
type WafBlockUrlDetailReq struct {
	Id string `json:"id"  form:"id"` //Block Url唯一键
}
type WafBlockUrlEditReq struct {
	Id          string `json:"id"`                               //Block url唯一键
	HostCode    string `json:"host_code"`                        //网站唯一码（主要键）
	CompareType string `json:"compare_type" form:"compare_type"` //对比方式
	Url         string `json:"url"`                              //Block url
	Remarks     string `json:"remarks"`                          //备注
}

// 批量删除请求结构体
type WafBlockUrlBatchDelReq struct {
	Ids []string `json:"ids" binding:"required"` // 要删除的ID列表
}

// 全部删除请求结构体
type WafBlockUrlDelAllReq struct {
	HostCode string `json:"host_code"` // 网站唯一码，为空则删除所有
}
