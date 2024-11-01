package response

import "SamWaf/model"

type WafSslConfigRep struct {
	model.SslConfig
	ExpirationInfo string `json:"expiration_info"   form:"expiration_info"`
}
