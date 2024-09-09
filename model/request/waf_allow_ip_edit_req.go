package request

type WafAllowIpEditReq struct {
	Id       string `json:"id"`        //白名单IP唯一键
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Ip       string `json:"ip"`        //白名单ip
	Remarks  string `json:"remarks"`   //备注
}
