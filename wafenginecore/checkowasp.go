package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"net/http"
	"net/url"
	"strconv"
)

func (waf *WafEngine) CheckOwasp(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	if global.GCONFIG_RECORD_ENABLE_OWASP == 0 {
		return result
	}
	isInteeruption, interruption, err := global.GWAF_OWASP.ProcessRequest(r, *weblogbean)
	if err == nil && isInteeruption {
		result.IsBlock = true
		result.Title = "OWASP:" + strconv.Itoa(interruption.RuleID)
		result.Content = "访问不合法"
		weblogbean.RISK_LEVEL = 2
	}
	return result
}
