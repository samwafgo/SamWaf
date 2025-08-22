package request

import "SamWaf/model/common/request"

type WafAllowUrlAddReq struct {
	HostCode    string `json:"host_code"`                        //网站唯一码（主要键）
	CompareType string `json:"compare_type" form:"compare_type"` //对比方式
	Url         string `json:"url"`                              //白名单url
	Remarks     string `json:"remarks"`                          //备注
}
type WafAllowUrlDelReq struct {
	Id string `json:"id"  form:"id"` //白名单url唯一键
}

type WafAllowUrlDetailReq struct {
	Id string `json:"id"  form:"id"` //白名单Url唯一键
}
type WafAllowUrlEditReq struct {
	Id          string `json:"id"`                               //白名单url唯一键
	HostCode    string `json:"host_code"`                        //网站唯一码（主要键）
	CompareType string `json:"compare_type" form:"compare_type"` //对比方式
	Url         string `json:"url"`                              //白名单url
	Remarks     string `json:"remarks"`                          //备注
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
