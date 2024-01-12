package request

type WafSystemConfigAddReq struct {
	Item     string `json:"item" form:"item"`           //item
	Value    string `json:"value" form:"value"`         //value
	ItemType string `json:"item_type" form:"item_type"` //item_type
	Options  string `json:"options" form:"options"`     //options
	Remarks  string `json:"remarks" form:"remarks"`     //备注
}
