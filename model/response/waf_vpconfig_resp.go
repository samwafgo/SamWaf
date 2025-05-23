package response

// WafVpConfigIpWhitelistGetResp IP白名单获取响应
type WafVpConfigIpWhitelistGetResp struct {
	IpWhitelist string `json:"ip_whitelist"` // IP白名单，多个IP用逗号分隔
}
