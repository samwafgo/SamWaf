package request

type WafLoadBalanceEditReq struct {
	Id          string `json:"id"`          //唯一键
	HostCode    string `json:"host_code"`   //网站唯一码（主要键）
	Remote_port int    `json:"remote_port"` //远端端口
	Remote_ip   string `json:"remote_ip"`   //远端指定IP
	Weight      int    `json:"weight"`      //权重
	Remarks     string `json:"remarks"`     //备注
}
