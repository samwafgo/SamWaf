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
}
type PublicApiGroup struct {
	LoginRouter
}

var ApiGroupApp = new(ApiGroup)
var PublicApiGroupApp = new(PublicApiGroup)
