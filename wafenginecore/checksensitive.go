package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	goahocorasick "github.com/samwafgo/ahocorasick"
	"net/http"
	"net/url"
	"strings"
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
	matchURLResult := waf.SensitiveManager.MultiPatternSearch([]rune(weblogbean.URL), false)
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
			words := processSensitiveWords(matchURLResult, "out")
			result.IsBlock = false
			weblogbean.GUEST_IDENTIFICATION = "触发敏感词"
			weblogbean.RULE = "敏感词检测：" + string(matchURLResult[0].Word)
			waf.ReplaceURLContent(r, words, global.GWAF_HTTP_SENSITIVE_REPLACE_STRING)
		}

		return result
	}
	matchBodyResult := waf.SensitiveManager.MultiPatternSearch([]rune(weblogbean.BODY), false)
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
			words := processSensitiveWords(matchBodyResult, "out")
			result.IsBlock = false
			weblogbean.GUEST_IDENTIFICATION = "触发敏感词"
			weblogbean.RULE = "敏感词检测：" + strings.Join(words, ",")
			waf.ReplaceBodyContent(r, words, global.GWAF_HTTP_SENSITIVE_REPLACE_STRING)
		}
		return result
	}
	return result
}

// 排除某个
func processSensitiveWords(input []*goahocorasick.Term, except string) []string {
	replaceStringsMap := make(map[string]bool) // 使用map去重
	var replaceStrings []string

	for _, term := range input {
		sensitive := term.CustomData.(model.Sensitive)
		if sensitive.CheckDirection == except {
			continue
		}
		if sensitive.Action == "replace" {
			// 检查是否已经存在，避免重复添加
			if !replaceStringsMap[sensitive.Content] {
				replaceStringsMap[sensitive.Content] = true
				replaceStrings = append(replaceStrings, sensitive.Content)
			}
		}
	}
	return replaceStrings
}
