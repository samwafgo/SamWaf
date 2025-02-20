package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
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
	if !waf.CheckRequestSensitive() {
		return result
	}
	//敏感词检测
	matchURLResult := waf.SensitiveManager.MultiPatternSearch([]rune(weblogbean.URL), true)
	if len(matchURLResult) > 0 {
		sensitive := matchURLResult[0].CustomData.(model.Sensitive)
		if sensitive.CheckDirection == "out" {
			return result
		}
		weblogbean.RISK_LEVEL = 1
		if sensitive.Action == "deny" {
			result.IsBlock = true
			result.Title = "敏感词检测：" + string(matchURLResult[0].Word)
			result.Content = "敏感词内容"
		} else {
			result.IsBlock = false
			weblogbean.GUEST_IDENTIFICATION = "触发敏感词"
			weblogbean.RULE = "敏感词检测：" + string(matchURLResult[0].Word)
			waf.ReplaceURLContent(r, string(matchURLResult[0].Word), global.GWAF_HTTP_SENSITIVE_REPLACE_STRING)
		}

		return result
	}
	matchBodyResult := waf.SensitiveManager.MultiPatternSearch([]rune(weblogbean.BODY), true)
	if len(matchBodyResult) > 0 {
		sensitive := matchBodyResult[0].CustomData.(model.Sensitive)
		if sensitive.CheckDirection == "out" {
			return result
		}
		weblogbean.RISK_LEVEL = 1
		if sensitive.Action == "deny" {
			result.IsBlock = true
			result.Title = "敏感词检测：" + string(matchBodyResult[0].Word)
			result.Content = "敏感词内容"
		} else {
			result.IsBlock = false
			weblogbean.GUEST_IDENTIFICATION = "触发敏感词"
			weblogbean.RULE = "敏感词检测：" + string(matchBodyResult[0].Word)
			waf.ReplaceBodyContent(r, string(matchBodyResult[0].Word), global.GWAF_HTTP_SENSITIVE_REPLACE_STRING)
		}
		return result
	}
	return result
}
