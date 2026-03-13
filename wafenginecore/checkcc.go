package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
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
	// 根据IP模式选择使用的IP（从 Host 级别读取）
	clientIP := model.GetClientIPByMode(hostTarget.Host.IPMode, weblogbean.NetSrcIp, weblogbean.SRC_IP)
	// cc 防护 (局部检测)
	if hostTarget.PluginIpRateLimiter != nil {
		isCheckCC := false
		if hostTarget.AntiCCBean.IsEnableRule {
			if hostTarget.PluginIpRateLimiter.Rule != nil {
				if hostTarget.PluginIpRateLimiter.Rule.KnowledgeBase != nil {
					ruleMatchs, err := hostTarget.PluginIpRateLimiter.Rule.Match("MF", weblogbean)
					if err == nil {
						if len(ruleMatchs) > 0 {
							isCheckCC = true
							zlog.Debug("CheckCC ruleMatchs: %v", ruleMatchs)
						}
					}
				}
			}
		} else {
			isCheckCC = true
		}
		if isCheckCC {
			if !hostTarget.PluginIpRateLimiter.Allow(clientIP) {
				weblogbean.RISK_LEVEL = 1
				result.IsBlock = true
				result.Title = "【局部】触发IP频次访问限制"
				result.Content = "您的访问被阻止超量了"
				cacheKey := enums.CACHE_CCVISITBAN_PRE + clientIP
				//将该IP添加到封禁里
				global.GCACHE_WAFCACHE.SetWithTTl(cacheKey, 1, time.Duration(hostTarget.AntiCCBean.LockIPMinutes)*time.Minute)
				return result
			}
		} else {
			return result
		}
	}

	// cc 防护 （全局检测）
	if waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].Host.GUARD_STATUS == 1 && waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].PluginIpRateLimiter != nil {
		if !waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].PluginIpRateLimiter.Allow(clientIP) {
			weblogbean.RISK_LEVEL = 1
			result.IsBlock = true
			result.Title = "【全局】触发IP频次访问限制"
			result.Content = "您的访问被阻止超量了"
			cacheKey := enums.CACHE_CCVISITBAN_PRE + clientIP
			//将该IP添加到封禁里
			global.GCACHE_WAFCACHE.SetWithTTl(cacheKey, 1, time.Duration(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].AntiCCBean.LockIPMinutes)*time.Minute)
			return result
		}
	}
	return result
}
