package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/libinjection-go"
	"SamWaf/model/detection"
	"net/url"
)

/*
*
检测扫描工具
*/
func (waf *WafEngine) CheckSan(weblogbean *innerbean.WebLog, formValue url.Values) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	var scanFlag = false
	if libinjection.IsScan(weblogbean) {
		scanFlag = true
	}
	if scanFlag == true {
		weblogbean.RISK_LEVEL = 1

		result.IsBlock = true
		result.Title = "扫描工具"
		result.Content = "请正确访问"
		return result
	}
	return result
}