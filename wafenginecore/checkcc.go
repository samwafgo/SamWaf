package wafenginecore

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"net/http"
	"net/url"
	"time"
)

/*
*
检测cc
*/
func (waf *WafEngine) CheckCC(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	// cc 防护 (局部检测 )
	if waf.HostTarget[weblogbean.HOST].PluginIpRateLimiter != nil {
		limiter := waf.HostTarget[weblogbean.HOST].PluginIpRateLimiter.GetLimiter(weblogbean.SRC_IP)
		if !limiter.Allow() {
			weblogbean.RISK_LEVEL = 1
			result.IsBlock = true
			result.Title = "触发IP频次访问限制1"
			result.Content = "您的访问被阻止超量了1"
			cacheKey := enums.CACHE_CCVISITBAN_PRE + weblogbean.SRC_IP
			//将该IP添加到封禁里
			global.GCACHE_WAFCACHE.SetWithTTl(cacheKey, 1, time.Duration(waf.HostTarget[weblogbean.HOST].AntiCCBean.LockIPMinutes)*time.Minute)
			return result
		}
	}
	// cc 防护 （全局检测 ）
	if waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].Host.GUARD_STATUS == 1 && waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].PluginIpRateLimiter != nil {
		limiter := waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].PluginIpRateLimiter.GetLimiter(weblogbean.SRC_IP)
		if !limiter.Allow() {
			weblogbean.RISK_LEVEL = 1
			result.IsBlock = true
			result.Title = "【全局】触发IP频次访问限制"
			result.Content = "您的访问被阻止超量了"
			cacheKey := enums.CACHE_CCVISITBAN_PRE + weblogbean.SRC_IP
			//将该IP添加到封禁里
			global.GCACHE_WAFCACHE.SetWithTTl(cacheKey, 1, time.Duration(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].AntiCCBean.LockIPMinutes)*time.Minute)
			return result
		}
	}
	return result
}
