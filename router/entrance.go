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
}
type PublicApiGroup struct {
	LoginRouter
}

var ApiGroupApp = new(ApiGroup)
var PublicApiGroupApp = new(PublicApiGroup)
