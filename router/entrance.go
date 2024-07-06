package router

type ApiGroup struct {
	HostRouter
	LogRouter
	RuleRouter
	EngineRouter
	StatRouter
	WhiteIpRouter
	WhiteUrlRouter
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
	CenterRouter
}
type PublicApiGroup struct {
	LoginRouter
	CenterPublicRouter
}

var ApiGroupApp = new(ApiGroup)
var PublicApiGroupApp = new(PublicApiGroup)
