package request

type WafBlockIpEditReq struct {
	Id       string `json:"id"`        //Block IP唯一键
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Ip       string `json:"ip"`        //Block ip
	Remarks  string `json:"remarks"`   //备注
}
