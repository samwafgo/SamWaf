package request

// WafVpConfigIpWhitelistUpdateReq IP白名单更新请求
type WafVpConfigIpWhitelistUpdateReq struct {
	IpWhitelist string `json:"ip_whitelist"` // IP白名单，多个IP用逗号分隔
}

// WafVpConfigManageTrustedProxiesUpdateReq 管理端可信代理网段更新请求
type WafVpConfigManageTrustedProxiesUpdateReq struct {
	TrustedProxies string `json:"trusted_proxies"` // 可信代理网段（CIDR/IP，逗号分隔，留空=不信任任何代理头）
}

// WafVpConfigCorsAllowOriginsUpdateReq CORS 跨域来源白名单更新请求
type WafVpConfigCorsAllowOriginsUpdateReq struct {
	CorsAllowOrigins string `json:"cors_allow_origins"` // CORS 跨域来源白名单（逗号分隔；回环/本机始终放行，无需填写）
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

// WafVpConfigSslForceHttpsUpdateReq 管理端仅允许HTTPS开关更新请求
type WafVpConfigSslForceHttpsUpdateReq struct {
	ForceHttps bool `json:"force_https"` // 是否仅允许HTTPS访问（开启后纯HTTP请求301跳转到HTTPS）
}

// WafVpConfigSslBindCertUpdateReq 管理端证书绑定证书夹更新请求
type WafVpConfigSslBindCertUpdateReq struct {
	SslConfigId string `json:"ssl_config_id"` // 绑定的证书夹(SslConfig)ID，为空表示解绑
}

// WafVpConfigSecurityEntryUpdateReq 安全路径入口更新请求
type WafVpConfigSecurityEntryUpdateReq struct {
	EntryEnable bool   `json:"entry_enable"` // 是否启用安全路径
	EntryPath   string `json:"entry_path"`   // 安全路径码，为空时自动生成
}

// WafVpConfigNoticeTitleUpdateReq 通知标题前缀更新请求
type WafVpConfigNoticeTitleUpdateReq struct {
	NoticeTitle string `json:"notice_title"` // 通知消息标题前缀，用于区分多实例
}

// WafVpConfigDomainWhitelistUpdateReq 域名白名单更新请求
type WafVpConfigDomainWhitelistUpdateReq struct {
	DomainWhitelist string `json:"domain_whitelist"` // 多个域名用逗号分隔，为空表示不限制
}
