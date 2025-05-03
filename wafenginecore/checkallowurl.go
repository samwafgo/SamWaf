package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
	"strings"
)

/*
*
检测允许的URL
返回是否满足条件
*/
func (waf *WafEngine) CheckAllowURL(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}

	// 将请求URL转为小写，用于不区分大小写的比较
	lowerURL := strings.ToLower(weblogbean.URL)

	//url白名单策略（局部）
	if hostTarget.UrlWhiteLists != nil {
		for i := 0; i < len(hostTarget.UrlWhiteLists); i++ {
			// 将规则URL也转为小写
			lowerRuleURL := strings.ToLower(hostTarget.UrlWhiteLists[i].Url)

			if (hostTarget.UrlWhiteLists[i].CompareType == "等于" && lowerRuleURL == lowerURL) ||
				(hostTarget.UrlWhiteLists[i].CompareType == "前缀匹配" && strings.HasPrefix(lowerURL, lowerRuleURL)) ||
				(hostTarget.UrlWhiteLists[i].CompareType == "后缀匹配" && strings.HasSuffix(lowerURL, lowerRuleURL)) ||
				(hostTarget.UrlWhiteLists[i].CompareType == "包含匹配" && strings.Contains(lowerURL, lowerRuleURL)) {
				result.JumpGuardResult = true
				break
			}
		}
	}

	//url白名单策略（全局）
	if waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].Host.GUARD_STATUS == 1 && waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlWhiteLists != nil {
		for i := 0; i < len(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlWhiteLists); i++ {
			// 将全局规则URL也转为小写
			lowerGlobalRuleURL := strings.ToLower(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlWhiteLists[i].Url)

			if (waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlWhiteLists[i].CompareType == "等于" && lowerGlobalRuleURL == lowerURL) ||
				(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlWhiteLists[i].CompareType == "前缀匹配" && strings.HasPrefix(lowerURL, lowerGlobalRuleURL)) ||
				(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlWhiteLists[i].CompareType == "后缀匹配" && strings.HasSuffix(lowerURL, lowerGlobalRuleURL)) ||
				(waf.HostTarget[global.GWAF_GLOBAL_HOST_NAME].UrlWhiteLists[i].CompareType == "包含匹配" && strings.Contains(lowerURL, lowerGlobalRuleURL)) {
				result.JumpGuardResult = true
				break
			}
		}
	}
	return result
}
