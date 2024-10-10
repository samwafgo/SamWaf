package response

import "SamWaf/model"

type WafSslConfigRep struct {
	model.SslConfig
	ExpirationInfo string `json:"expiration_info"   form:"expiration_info"`
	KeyPath        string `json:"key_path"   form:"key_path"`
	CertPath       string `json:"cert_path"   form:"cert_path"`
}
