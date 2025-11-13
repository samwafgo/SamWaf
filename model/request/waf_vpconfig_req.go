package request

// WafVpConfigIpWhitelistUpdateReq IP白名单更新请求
type WafVpConfigIpWhitelistUpdateReq struct {
	IpWhitelist string `json:"ip_whitelist"` // IP白名单，多个IP用逗号分隔
}

// WafVpConfigSslEnableUpdateReq SSL启用状态更新请求
type WafVpConfigSslEnableUpdateReq struct {
	SslEnable bool `json:"ssl_enable"` // 是否启用SSL
}

// WafVpConfigSslUploadReq SSL证书上传请求
type WafVpConfigSslUploadReq struct {
	CertContent string `json:"cert_content"` // 证书内容
	KeyContent  string `json:"key_content"`  // 私钥内容
}
