package api

import "SamWaf/service/waf_service"

type APIGroup struct {
	WafHostAPi
	WafStatApi
	WafLogAPi
	WafRuleAPi
	WafEngineApi
}

var APIGroupAPP = new(APIGroup)
var (
	wafHostService = waf_service.WafHostServiceApp
	wafLogService  = waf_service.WafLogServiceApp
	wafStatService = waf_service.WafStatServiceApp
	wafRuleService = waf_service.WafRuleServiceApp
)
