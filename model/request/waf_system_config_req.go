package request

import "SamWaf/model/common/request"

type WafSystemConfigAddReq struct {
	ItemClass string `json:"item_class"`                 //所属分类
	Item      string `json:"item" form:"item"`           //item
	Value     string `json:"value" form:"value"`         //value
	ItemType  string `json:"item_type" form:"item_type"` //item_type
	Options   string `json:"options" form:"options"`     //options
	Remarks   string `json:"remarks" form:"remarks"`     //备注
}
type WafSystemConfigDelReq struct {
	Id string `json:"id"  form:"id"` //唯一键
}
type WafSystemConfigDetailReq struct {
	Id string `json:"id"  form:"id"` //唯一键
}
type WafSystemConfigEditReq struct {
	Id        string `json:"id"`
	ItemClass string `json:"item_class"`                 //所属分类
	Item      string `json:"item" form:"item"`           //item
	Value     string `json:"value" form:"value"`         //value
	ItemType  string `json:"item_type" form:"item_type"` //item_type
	Options   string `json:"options" form:"options"`     //options
	Remarks   string `json:"remarks" form:"remarks"`     //备注
}
type WafSystemConfigSearchReq struct {
	Item    string `json:"item" form:"item"`
	Remarks string `json:"remarks" form:"remarks"`
	request.PageInfo
}
