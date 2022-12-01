package response

type AllHostRep struct {
	Code string `json:"value"` //唯一码
	Host string `json:"label"` //域名
}
