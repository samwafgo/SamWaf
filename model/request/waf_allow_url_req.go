package request

import "SamWaf/model/common/request"

type WafAllowUrlAddReq struct {
	HostCode    string `json:"host_code" binding:"required"`                         //网站唯一码（主要键）
	CompareType string `json:"compare_type" form:"compare_type"  binding:"required"` //对比方式
	Url         string `json:"url" binding:"required"`                               //白名单url
	Remarks     string `json:"remarks"`                                              //备注
	IsEnable    *int   `json:"is_enable"`                                            //启用状态：nil=新增默认启用/编辑不改动，0停用 1启用
}
type WafAllowUrlDelReq struct {
	Id string `json:"id"  form:"id"` //白名单url唯一键
}

type WafAllowUrlDetailReq struct {
	Id string `json:"id"  form:"id"` //白名单Url唯一键
}
type WafAllowUrlEditReq struct {
	Id          string `json:"id" binding:"required"`                               //白名单url唯一键
	HostCode    string `json:"host_code" binding:"required"`                        //网站唯一码（主要键）
	CompareType string `json:"compare_type" form:"compare_type" binding:"required"` //对比方式
	Url         string `json:"url" binding:"required"`                              //白名单url
	Remarks     string `json:"remarks"`                                             //备注
	IsEnable    *int   `json:"is_enable"`                                           //启用状态：nil=新增默认启用/编辑不改动，0停用 1启用
}

type WafAllowUrlSearchReq struct {
	HostCode string `json:"host_code" ` //主机码
	Url      string `json:"url"`        //白名单url
	request.PageInfo
}

type WafAllowUrlBatchDelReq struct {
	Ids []string `json:"ids" form:"ids"` //白名单url唯一键数组
}

type WafAllowUrlDelAllReq struct {
	HostCode string `json:"host_code" form:"host_code"` //网站唯一码
}

type WafAllowUrlToggleReq struct {
	Id       string `json:"id" form:"id" binding:"required"`               //条目唯一键
	IsEnable *int   `json:"is_enable" form:"is_enable" binding:"required"` //1启用 0停用（必填，防漏字段被当成停用）
}
