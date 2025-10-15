package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"net/url"
	"strconv"
)

func (waf *WafEngine) CheckOwasp(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	hostDefense := model.ParseHostsDefense(hostTarget.Host.DEFENSE_JSON)
	if global.GCONFIG_RECORD_ENABLE_OWASP == 1 || hostDefense.DEFENSE_OWASP_SET == 1 {
		isInteeruption, interruption, err := global.GWAF_OWASP.ProcessRequest(r, *weblogbean)
		if err == nil && isInteeruption {
			result.IsBlock = true
			// 使用中断对象中的详细信息
			if interruption.Data != "" {
				result.Title = "OWASP:" + strconv.Itoa(interruption.RuleID) + interruption.Data
			}
			result.Content = "访问不合法"
			weblogbean.RISK_LEVEL = 2
		}
	}

	return result
}
