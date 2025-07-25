package api

import "SamWaf/service/waf_service"

type APIGroup struct {
	WafHostAPi
	WafStatApi
	WafLogAPi
	WafRuleAPi
	WafEngineApi
	WafAllowIpApi
	WafAllowUrlApi
	WafLdpUrlApi
	WafAntiCCApi
	WafBlockIpApi
	WafBlockUrlApi
	WafAccountApi
	WafAccountLogApi
	WafLoginApi
	WafSysLogApi
	WafWebSocketApi
	WafSysInfoApi
	WafSystemConfigApi
	WafCommonApi
	WafOneKeyModApi
	CenterApi
	WafLicenseApi
	WafSensitiveApi
	WafLoadBalanceApi
	WafSslConfigApi
	WafBatchTaskApi
	WafSslOrderApi
	WafSslExpireApi
	WafHttpAuthBaseApi
	WafTaskApi
	WafBlockingPageApi
	WafGPTApi
	WafOtpApi
	WafAnalysisApi
	WafPrivateInfoApi
	WafPrivateGroupApi
	WafCacheRuleApi
	WafTunnelApi
	WafVpConfigApi
	WafFileApi
	WafSystemMonitorApi
}

var APIGroupAPP = new(APIGroup)
var (
	wafHostService     = waf_service.WafHostServiceApp
	wafLogService      = waf_service.WafLogServiceApp
	wafStatService     = waf_service.WafStatServiceApp
	wafRuleService     = waf_service.WafRuleServiceApp
	wafIpAllowService  = waf_service.WafWhiteIpServiceApp
	wafUrlAllowService = waf_service.WafWhiteUrlServiceApp
	wafLdpUrlService   = waf_service.WafLdpUrlServiceApp
	wafAntiCCService   = waf_service.WafAntiCCServiceApp

	wafIpBlockService  = waf_service.WafBlockIpServiceApp
	wafUrlBlockService = waf_service.WafBlockUrlServiceApp

	wafAccountService    = waf_service.WafAccountServiceApp
	wafAccountLogService = waf_service.WafAccountLogServiceApp
	wafTokenInfoService  = waf_service.WafTokenInfoServiceApp

	wafSysLogService       = waf_service.WafSysLogServiceApp
	wafSystemConfigService = waf_service.WafSystemConfigServiceApp
	wafDelayMsgService     = waf_service.WafDelayMsgServiceApp

	wafShareDbService = waf_service.WafShareDbServiceApp

	wafOneKeyModService = waf_service.WafOneKeyModServiceApp

	CenterService = waf_service.CenterServiceApp

	wafSensitiveService = waf_service.WafSensitiveServiceApp

	wafLoadBalanceService = waf_service.WafLoadBalanceServiceApp

	wafSslConfigService = waf_service.WafSslConfigServiceApp

	wafBatchTaskService = waf_service.WafBatchServiceApp

	wafSslOrderService = waf_service.WafSSLOrderServiceApp

	wafSslExpireService = waf_service.WafSslExpireServiceApp

	wafHttpAuthBaseService = waf_service.WafHttpAuthBaseServiceApp

	TaskService = waf_service.WafTaskServiceApp

	wafBlockingPageService = waf_service.WafBlockingPageServiceApp

	wafOtpService = waf_service.WafOtpServiceApp

	wafAnalysisService = waf_service.WafAnalysisServiceApp

	wafPrivateInfoService  = waf_service.WafPrivateInfoServiceApp
	wafPrivateGroupService = waf_service.WafPrivateGroupServiceApp
	wafCacheRuleService    = waf_service.WafCacheRuleServiceApp
	wafTunnelService       = waf_service.WafTunnelServiceApp

	wafMonitorService = waf_service.WafSystemMonitorServiceApp
)
