package request

type WafSystemConfigEditReq struct {
	Id      string `json:"id"`
	Item    string `json:"item" form:"item"`       //item
	Value   string `json:"value" form:"value"`     //value
	Remarks string `json:"remarks" form:"remarks"` //备注
}
