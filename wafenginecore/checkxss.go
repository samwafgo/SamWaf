package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/libinjection-go"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
)

/*
*
检测xss
*/
func (waf *WafEngine) CheckXss(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	var xssFlag = false
	if libinjection.IsXSS(weblogbean.RawQuery) ||
		libinjection.IsXSS(weblogbean.POST_FORM) {
		xssFlag = true
	}
	if xssFlag == false {
		for _, value := range formValue {
			for _, v := range value {
				if libinjection.IsXSS(v) {
					//xssFlag = true
				}
			}
		}
	}
	if xssFlag == true {
		weblogbean.RISK_LEVEL = 2
		result.IsBlock = true
		result.Title = "XSS跨站注入"
		result.Content = "请正确访问"
		return result
	}
	return result
}
