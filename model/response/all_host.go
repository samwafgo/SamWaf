package response

type AllHostRep struct {
	Code string `json:"host_code"` //唯一码
	Host string `json:"host"`      //域名
}
