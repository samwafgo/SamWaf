package router

type ApiGroup struct {
	HostRouter
	LogRouter
	RuleRouter
	EngineRouter
	StatRouter
	AllowIpRouter
	AllowUrlRouter
	LdpUrlRouter
	AntiCCRouter
	BlockIpRouter
	BlockUrlRouter
	AccountRouter
	AccountLogRouter
	LoginOutRouter
	SysLogRouter
	WebSocketRouter
	WebSysInfoRouter
	SystemConfigRouter
	WafCommonRouter
	OneKeyModRouter
	WafLicenseRouter
	CenterRouter
	SensitiveRouter
	LoadBalanceRouter
	SslConfigRouter
	BatchTaskRouter
	SslOrderRouter
	WafSslExpireRouter
	WafHttpAuthBaseRouter
	WafTaskRouter
	WafBlockingPageRouter
	WafGPTRouter
	WafOtpRouter
	AnalysisRouter
	WafPrivateInfoRouter
	WafPrivateGroupRouter
	WafCacheRuleRouter
	WafTunnelRouter
	WafVpConfigRouter
}
type PublicApiGroup struct {
	LoginRouter
	CenterPublicRouter
}

var ApiGroupApp = new(ApiGroup)
var PublicApiGroupApp = new(PublicApiGroup)
