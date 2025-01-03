package response

import "SamWaf/model"

type WafSslConfigRep struct {
	model.SslConfig
	ExpirationInfo string `json:"expiration_info"   form:"expiration_info"`
}

type WafSslCheckRep struct {
	model.SslExpire
	ExpirationInfo string `json:"expiration_info"   form:"expiration_info"`
	ExpirationDay  int    `json:"expiration_day"   form:"expiration_day"`
}
