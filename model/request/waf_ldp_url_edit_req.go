package request

type WafLdpUrlEditReq struct {
	Id          string `json:"id"`           //隐私保护url唯一键
	HostCode    string `json:"host_code"`    //网站唯一码（主要键）
	CompareType string `json:"compare_type"` //对比方式
	Url         string `json:"url"`          //隐私保护url
	Remarks     string `json:"remarks"`      //备注
}
