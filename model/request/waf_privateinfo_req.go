package request

import "SamWaf/model/common/request"

type WafPrivateInfoAddReq struct {
	PrivateKey              string `json:"private_key" form:"private_key"`
	PrivateValue            string `json:"private_value" form:"private_value"`
	PrivateGroupName        string `json:"private_group_name"`         //分组名称
	PrivateGroupBelongCloud string `json:"private_group_belong_cloud"` //分组归属云
	Remarks                 string `json:"remarks" form:"remarks"`
}
type WafPrivateInfoEditReq struct {
	PrivateKey              string `json:"private_key" form:"private_key"`
	PrivateValue            string `json:"private_value" form:"private_value"`
	PrivateGroupName        string `json:"private_group_name"`         //分组名称
	PrivateGroupBelongCloud string `json:"private_group_belong_cloud"` //分组归属云
	Remarks                 string `json:"remarks" form:"remarks"`
}
type WafPrivateInfoDetailReq struct {
	Id string `json:"id"   form:"id"`
}
type WafPrivateInfoDelReq struct {
	Id string `json:"id"   form:"id"`
}
type WafPrivateInfoSearchReq struct {
	request.PageInfo
}
