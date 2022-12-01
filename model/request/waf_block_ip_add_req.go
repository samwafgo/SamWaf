package request

type WafBlockIpAddReq struct {
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Ip       string `json:"ip"`        //Block ip
	Remarks  string `json:"remarks"`   //备注
}
