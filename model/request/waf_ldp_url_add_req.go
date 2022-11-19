package request

type WafLdpUrlAddReq struct {
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Url      string `json:"url"`       //加隐私保护的url
	Remarks  string `json:"remarks"`   //备注
}
