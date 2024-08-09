package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"net/url"
	"strings"
)

/*
*
检测不允许访问的 url
返回是否满足条件
*/
func (waf *WafEngine) CheckDenyURL(weblogbean innerbean.WebLog, formValue url.Values) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	//url黑名单策略-(局部) （待优化性能）
	if waf.HostTarget[weblogbean.HOST].UrlBlockLists != nil {
		for i := 0; i < len(waf.HostTarget[weblogbean.HOST].UrlBlockLists); i++ {
			if (waf.HostTarget[weblogbean.HOST].UrlBlockLists[i].CompareType == "等于" && waf.HostTarget[weblogbean.HOST].UrlBlockLists[i].Url == weblogbean.URL) ||
				(waf.HostTarget[weblogbean.HOST].UrlBlockLists[i].CompareType == "前缀匹配" && strings.HasPrefix(weblogbean.URL, waf.HostTarget[weblogbean.HOST].UrlBlockLists[i].Url)) ||
				(waf.HostTarget[weblogbean.HOST].UrlBlockLists[i].CompareType == "后缀匹配" && strings.HasSuffix(weblogbean.URL, waf.HostTarget[weblogbean.HOST].UrlBlockLists[i].Url)) ||
				(waf.HostTarget[weblogbean.HOST].UrlBlockLists[i].CompareType == "包含匹配" && strings.Contains(weblogbean.URL, waf.HostTarget[weblogbean.HOST].UrlBlockLists[i].Url)) {
				weblogbean.RISK_LEVEL = 1
				result.IsBlock = true
				result.Title = "URL黑名单"
				result.Content = "您的访问被阻止了URL限制"
				return result
			}
		}
	}
	//url黑名单策略-(全局) （待优化性能）
	if waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].Host.GUARD_STATUS == 1 && waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlBlockLists != nil {
		for i := 0; i < len(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlBlockLists); i++ {
			if (waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlBlockLists[i].CompareType == "等于" && waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlBlockLists[i].Url == weblogbean.URL) ||
				(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlBlockLists[i].CompareType == "前缀匹配" && strings.HasPrefix(weblogbean.URL, waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlBlockLists[i].Url)) ||
				(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlBlockLists[i].CompareType == "后缀匹配" && strings.HasSuffix(weblogbean.URL, waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlBlockLists[i].Url)) ||
				(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlBlockLists[i].CompareType == "包含匹配" && strings.Contains(weblogbean.URL, waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlBlockLists[i].Url)) {
				weblogbean.RISK_LEVEL = 1
				result.IsBlock = true
				result.Title = "【全局】URL黑名单"
				result.Content = "您的访问被阻止了URL限制"
				return result
			}
		}
	}
	return result
}
