package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafdefenserce"
	"net/http"
	"net/url"
)

/*
*
检测Rce
*/
func (waf *WafEngine) CheckRce(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	// 查询串已多轮解码；再逐个查已解码的表单值
	isRce, RceName := wafdefenserce.DetermineRCE(weblogbean.RawQuery, weblogbean.URL, weblogbean.COOKIES, weblogbean.BODY)
	if isRce == false {
		for _, values := range formValue {
			for _, v := range values {
				if ok, name := wafdefenserce.DetermineRCE(v); ok {
					isRce, RceName = ok, name
					break
				}
			}
			if isRce {
				break
			}
		}
	}
	if isRce == true {
		weblogbean.RISK_LEVEL = 3
		result.IsBlock = true
		result.Title = "RCE:" + RceName
		result.Content = "请正确访问"
		return result
	}
	return result
}
