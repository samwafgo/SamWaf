package response

// WafVpConfigIpWhitelistGetResp IP白名单获取响应
type WafVpConfigIpWhitelistGetResp struct {
	IpWhitelist string `json:"ip_whitelist"` // IP白名单，多个IP用逗号分隔
}

// WafVpConfigSslStatusGetResp SSL状态获取响应
type WafVpConfigSslStatusGetResp struct {
	SslEnable    bool   `json:"ssl_enable"`     // 是否启用SSL
	HasCert      bool   `json:"has_cert"`       // 是否已上传证书
	CertExpireAt string `json:"cert_expire_at"` // 证书过期时间
	CertDomain   string `json:"cert_domain"`    // 证书域名
	CertContent  string `json:"cert_content"`   // 证书内容
	KeyContent   string `json:"key_content"`    // 私钥内容
}
