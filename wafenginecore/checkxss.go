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
	// 使用逐参数值检测，避免参数名（如 style、href、filter 等）被 libinjection 误当 HTML 属性导致误报
	if libinjection.IsXSSInQueryValues(weblogbean.RawQuery) ||
		libinjection.IsXSSInQueryValues(weblogbean.POST_FORM) {
		xssFlag = true
	}
	if xssFlag == false {
		for _, value := range formValue {
			for _, v := range value {
				// 注意：此处暂时不启用，formValue 中的值在某些业务场景下存在误报风险。
				// 若需启用，使用 libinjection.IsXSSSingleValue(v) 以降低误报率（预过滤+逐值检测）。
				_ = v
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
