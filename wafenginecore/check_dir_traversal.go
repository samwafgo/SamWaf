package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/libinjection-go"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
)

// CheckDirTraversal 穿越漏洞检测
func (waf *WafEngine) CheckDirTraversal(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	var flag = false
	//检测sql注入
	if libinjection.HasDirTraversal(weblogbean.RawQuery) ||
		libinjection.HasDirTraversal(weblogbean.BODY) {
		flag = true
	}
	if flag == false {
		for _, value := range formValue {
			for _, v := range value {
				if libinjection.HasDirTraversal(v) {
					flag = true
				}
			}
		}
	}
	if flag == true {
		weblogbean.RISK_LEVEL = 2
		result.IsBlock = true
		result.Title = "目录穿越漏洞"
		result.Content = "请正确访问"
		return result
	}
	return result
}
