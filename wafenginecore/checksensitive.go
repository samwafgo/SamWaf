package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
)

/*
*
检测敏感词
*/
func (waf *WafEngine) CheckSensitive(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	if len(waf.Sensitive) == 0 {
		return result
	}
	//敏感词检测
	matchURLResult := waf.SensitiveManager.MultiPatternSearch([]rune(weblogbean.URL), true)
	if len(matchURLResult) > 0 {
		weblogbean.RISK_LEVEL = 1
		result.IsBlock = true
		result.Title = "敏感词检测：" + string(matchURLResult[0].Word)
		result.Content = "敏感词内容"
		return result
	}
	matchBodyResult := waf.SensitiveManager.MultiPatternSearch([]rune(weblogbean.BODY), true)
	if len(matchBodyResult) > 0 {
		weblogbean.RISK_LEVEL = 1
		result.IsBlock = true
		result.Title = "敏感词检测：" + string(matchBodyResult[0].Word)
		result.Content = "敏感词内容"
		return result
	}
	matchPostFromResult := waf.SensitiveManager.MultiPatternSearch([]rune(weblogbean.POST_FORM), true)
	if len(matchPostFromResult) > 0 {
		weblogbean.RISK_LEVEL = 1
		result.IsBlock = true
		result.Title = "敏感词检测：" + string(matchPostFromResult[0].Word)
		result.Content = "敏感词内容"
		return result
	}
	return result
}
