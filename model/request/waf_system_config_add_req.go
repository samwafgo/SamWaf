package request

type WafSystemConfigAddReq struct {
	Item    string `json:"item" form:"item"`       //item
	Value   string `json:"value" form:"value"`     //value
	Remarks string `json:"remarks" form:"remarks"` //备注
}
