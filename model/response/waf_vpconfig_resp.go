package response

// WafVpConfigIpWhitelistGetResp IP白名单获取响应
type WafVpConfigIpWhitelistGetResp struct {
	IpWhitelist string `json:"ip_whitelist"` // IP白名单，多个IP用逗号分隔
}

// WafVpConfigManageTrustedProxiesGetResp 管理端可信代理网段获取响应
type WafVpConfigManageTrustedProxiesGetResp struct {
	TrustedProxies string `json:"trusted_proxies"` // 可信代理网段（CIDR/IP，逗号分隔）
}

// WafVpConfigCorsAllowOriginsGetResp CORS 跨域来源白名单获取响应
type WafVpConfigCorsAllowOriginsGetResp struct {
	CorsAllowOrigins string `json:"cors_allow_origins"` // CORS 跨域来源白名单（逗号分隔）
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

// WafVpConfigSslForceHttpsGetResp 管理端仅允许HTTPS开关获取响应
type WafVpConfigSslForceHttpsGetResp struct {
	ForceHttps bool `json:"force_https"` // 是否仅允许HTTPS访问
}

// WafVpConfigSslBindCertGetResp 管理端证书绑定证书夹获取响应
type WafVpConfigSslBindCertGetResp struct {
	SslConfigId string `json:"ssl_config_id"` // 当前绑定的证书夹ID，空表示未绑定
	Domains     string `json:"domains"`       // 绑定证书夹适用的域名/IP（摘要）
	ValidTo     string `json:"valid_to"`      // 绑定证书夹到期时间（摘要）
}

// WafVpConfigSecurityEntryGetResp 安全路径入口获取响应
type WafVpConfigSecurityEntryGetResp struct {
	EntryEnable bool   `json:"entry_enable"` // 是否启用安全路径
	EntryPath   string `json:"entry_path"`   // 安全路径码
}

// WafVpConfigNoticeTitleGetResp 通知标题前缀获取响应
type WafVpConfigNoticeTitleGetResp struct {
	NoticeTitle string `json:"notice_title"` // 通知消息标题前缀
}

// WafVpConfigDomainWhitelistGetResp 域名白名单获取响应
type WafVpConfigDomainWhitelistGetResp struct {
	DomainWhitelist string `json:"domain_whitelist"`
}
