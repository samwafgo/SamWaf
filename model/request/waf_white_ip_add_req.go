package request

type WafWhiteIpAddReq struct {
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Ip       string `json:"ip"`        //白名单ip
	Remarks  string `json:"remarks"`   //备注
}
