package request

type WafAntiCCEditReq struct {
	Id       string `json:"id"`                          //白名单url唯一键
	HostCode string `json:"host_code"  form:"host_code"` //网站唯一码（主要键）
	Url      string `json:"url" form:"url"`              //白名单url
	Rate     int    `json:"rate"  form:"rate"`           //速率
	Limit    int    `json:"limit" form:"limit"`          //限制
	Remarks  string `json:"remarks" form:"remarks"`      //备注
}
