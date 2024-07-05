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
}
type PublicApiGroup struct {
	LoginRouter
	CenterRouter
}

var ApiGroupApp = new(ApiGroup)
var PublicApiGroupApp = new(PublicApiGroup)
