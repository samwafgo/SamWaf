package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/utils"
	"net/http"
	"net/url"
)

/*
*
检测不允许访问的 ip
返回是否满足条件
*/
func (waf *WafEngine) CheckDenyIP(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	//ip黑名单策略  （局部）
	if hostTarget.IPBlockLists != nil {
		for i := 0; i < len(hostTarget.IPBlockLists); i++ {
			if utils.CheckIPInCIDR(weblogbean.SRC_IP, hostTarget.IPBlockLists[i].Ip) {
				weblogbean.RISK_LEVEL = 1
				result.IsBlock = true
				result.Title = "IP黑名单"
				result.Content = "您的访问被阻止了IP限制"
				return result
			}
		}
	}
	//ip黑名单策略（全局）
	if waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].Host.GUARD_STATUS == 1 && waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].IPBlockLists != nil {
		for i := 0; i < len(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].IPBlockLists); i++ {
			if utils.CheckIPInCIDR(weblogbean.SRC_IP, waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].IPBlockLists[i].Ip) {
				weblogbean.RISK_LEVEL = 1
				result.IsBlock = true
				result.Title = "【全局】IP黑名单"
				result.Content = "您的访问被阻止了IP限制"
				return result
			}
		}
	}
	return result
}
