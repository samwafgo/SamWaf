package request

import "SamWaf/model/common/request"

type WafBlockUrlAddReq struct {
	HostCode    string `json:"host_code" binding:"required"`                         //网站唯一码（主要键）
	CompareType string `json:"compare_type" form:"compare_type"  binding:"required"` //对比方式
	Url         string `json:"url"  binding:"required"`                              //Block url
	Remarks     string `json:"remarks"`                                              //备注
	IsEnable    *int   `json:"is_enable"`                                            //启用状态：nil=新增默认启用/编辑不改动，0停用 1启用
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
	Id          string `json:"id" binding:"required"`                               //Block url唯一键
	HostCode    string `json:"host_code" binding:"required"`                        //网站唯一码（主要键）
	CompareType string `json:"compare_type" form:"compare_type" binding:"required"` //对比方式
	Url         string `json:"url" binding:"required"`                              //Block url
	Remarks     string `json:"remarks"`                                             //备注
	IsEnable    *int   `json:"is_enable"`                                           //启用状态：nil=新增默认启用/编辑不改动，0停用 1启用
}

// 批量删除请求结构体
type WafBlockUrlBatchDelReq struct {
	Ids []string `json:"ids" binding:"required"` // 要删除的ID列表
}

// 全部删除请求结构体
type WafBlockUrlDelAllReq struct {
	HostCode string `json:"host_code"` // 网站唯一码，为空则删除所有
}

type WafBlockUrlToggleReq struct {
	Id       string `json:"id" form:"id" binding:"required"`               //条目唯一键
	IsEnable *int   `json:"is_enable" form:"is_enable" binding:"required"` //1启用 0停用（必填，防漏字段被当成停用）
}
