package response

import "SamWaf/model"

type WafSslConfigRep struct {
	model.SslConfig
	ExpirationInfo string   `json:"expiration_info"   form:"expiration_info"`
	BindHosts      []string `json:"bind_hosts"   form:"bind_hosts"` // 绑定的主机列表
}

type WafSslCheckRep struct {
	model.SslExpire
	ExpirationInfo string `json:"expiration_info"   form:"expiration_info"`
	ExpirationDay  int    `json:"expiration_day"   form:"expiration_day"`
}
