package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/wafbot"
	"net/url"
)

/*
*
检测爬虫
*/
func (waf *WafEngine) CheckBot(weblogbean *innerbean.WebLog, formValue url.Values) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	isBot, isNormalBot, BotName := wafbot.DetermineNormalSearch(weblogbean.USER_AGENT, weblogbean.SRC_IP)
	if isBot == true {
		if isNormalBot {
			weblogbean.GUEST_IDENTIFICATION = BotName
		} else {
			weblogbean.GUEST_IDENTIFICATION = BotName
			weblogbean.RISK_LEVEL = 1

			result.IsBlock = true
			result.Title = BotName
			result.Content = "请正确访问"
			return result
		}
	}
	return result
}
