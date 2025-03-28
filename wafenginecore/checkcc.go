package wafenginecore

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
	"time"
)

/*
*
检测cc
*/
func (waf *WafEngine) CheckCC(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	// cc 防护 (局部检测 )
	if hostTarget.PluginIpRateLimiter != nil {

		if !hostTarget.PluginIpRateLimiter.Allow(weblogbean.NetSrcIp) {
			weblogbean.RISK_LEVEL = 1
			result.IsBlock = true
			result.Title = "【局部】触发IP频次访问限制"
			result.Content = "您的访问被阻止超量了"
			cacheKey := enums.CACHE_CCVISITBAN_PRE + weblogbean.NetSrcIp
			//将该IP添加到封禁里
			global.GCACHE_WAFCACHE.SetWithTTl(cacheKey, 1, time.Duration(hostTarget.AntiCCBean.LockIPMinutes)*time.Minute)
			return result
		}
	}
	// cc 防护 （全局检测 ）
	if waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].Host.GUARD_STATUS == 1 && waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].PluginIpRateLimiter != nil {
		if !waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].PluginIpRateLimiter.Allow(weblogbean.NetSrcIp) {
			weblogbean.RISK_LEVEL = 1
			result.IsBlock = true
			result.Title = "【全局】触发IP频次访问限制"
			result.Content = "您的访问被阻止超量了"
			cacheKey := enums.CACHE_CCVISITBAN_PRE + weblogbean.NetSrcIp
			//将该IP添加到封禁里
			global.GCACHE_WAFCACHE.SetWithTTl(cacheKey, 1, time.Duration(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].AntiCCBean.LockIPMinutes)*time.Minute)
			return result
		}
	}
	return result
}
