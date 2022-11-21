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
}

var ApiGroupApp = new(ApiGroup)
