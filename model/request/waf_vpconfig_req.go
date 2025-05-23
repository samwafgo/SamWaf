package request

// WafVpConfigIpWhitelistUpdateReq IP白名单更新请求
type WafVpConfigIpWhitelistUpdateReq struct {
	IpWhitelist string `json:"ip_whitelist"` // IP白名单，多个IP用逗号分隔
}
