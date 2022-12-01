package request

type WafBlockUrlAddReq struct {
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Url      string `json:"url"`       //Block url
	Remarks  string `json:"remarks"`   //备注
}
