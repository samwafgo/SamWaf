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
检测sqli
*/
func (waf *WafEngine) CheckSql(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	var sqlFlag = false
	//检测sql注入
	if libinjection.IsSQLiNotReturnPrint(weblogbean.RawQuery) ||
		libinjection.IsSQLiNotReturnPrint(weblogbean.BODY) ||
		libinjection.IsSQLiNotReturnPrint(weblogbean.POST_FORM) {
		sqlFlag = true
	}
	if sqlFlag == false {
		for _, value := range formValue {
			for _, v := range value {
				if libinjection.IsSQLiNotReturnPrint(v) {
					sqlFlag = true
				}
			}
		}
	}
	if sqlFlag == true {
		weblogbean.RISK_LEVEL = 2
		result.IsBlock = true
		result.Title = "SQL注入"
		result.Content = "请正确访问"
		return result
	}
	return result
}
