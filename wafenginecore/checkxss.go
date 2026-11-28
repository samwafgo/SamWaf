package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/libinjection-go"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/wafhttpcore"
	"net/http"
	"net/url"
	"regexp"
)

// reXSSExecSignal 可执行 XSS 上下文信号：真标签开(<字母/!/‌/)、事件处理器 on\w+=、js/data 伪协议。
// 用于给请求体逐值 XSS 加“第二信号”(D)：libinjection 命中 + 含执行信号才判，避免散文里孤立的
// < 或引号(如 JS 错误上报 token '<')被 libinjection 单信号误判。
var reXSSExecSignal = regexp.MustCompile(`(?i)<[a-z!/]|on\w+\s*=|javascript:|srcdoc\s*=|data:text/html`)

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
	ensureWebLogBodyClassified(r, weblogbean, &formValue)
	// 查询串/表单串检测：始终强制拦截（非本次请求体误报来源）
	xssHit := libinjection.IsXSSInQueryValues(weblogbean.RawQuery) ||
		libinjection.IsXSSInQueryValues(weblogbean.POST_FORM)
	// S1 二期：查询 GET 值叠 HTML 实体/unicode 解码后"多信号"判，补 htmlent(&lt;)/unicode_js(<)
	// 编码的 XSS。多信号(真标签/事件)+结构化跳过保证零新增误报(blaze 33k 白样本净新增 0)。
	if !xssHit {
		for _, values := range r.URL.Query() {
			for _, v := range values {
				if bodyValueIsXSS(v) {
					xssHit = true
					break
				}
			}
			if xssHit {
				break
			}
		}
	}
	if xssHit {
		weblogbean.RISK_LEVEL = 2
		result.IsBlock = true
		result.Title = "XSS跨站注入"
		result.Content = "请正确访问"
		return result
	}
	// 请求体+头部深度检测（formValue/JSON 逐值 + 自定义头 S1-4）：受 body_detect_mode 门控 + 结构化跳过(C) + 多信号(D) + 字段排除(E)
	if bodyDetectEnabled() && (waf.bodyXSSHit(formValue, weblogbean.BodyFields, weblogbean.BodyValues) || headerXSSHit(r)) {
		if bodyDetectBlocking() {
			weblogbean.RISK_LEVEL = 2
			result.IsBlock = true
			result.Title = "XSS跨站注入"
			result.Content = "请正确访问"
			return result
		}
		markBodyObserve(weblogbean, "XSS跨站注入")
	}
	return result
}

// bodyXSSHit 请求体逐值 XSS：按字段排除(E) + 跳过结构化数据值(C) + libinjection 命中且含执行信号(D)
func (waf *WafEngine) bodyXSSHit(formValue url.Values, bodyFields, bodyValues []string) bool {
	for key, vals := range formValue {
		if isBodyFieldExcluded(key) { // E：已知富文本字段整体跳过
			continue
		}
		if bodyValueIsXSS(key) {
			return true
		}
		for _, v := range vals {
			if bodyValueIsXSS(v) {
				return true
			}
		}
	}
	for i, v := range bodyValues {
		if isBodyFieldExcluded(fieldAt(bodyFields, i)) { // E
			continue
		}
		if bodyValueIsXSS(v) {
			return true
		}
	}
	return false
}

func bodyValueIsXSS(v string) bool {
	dv := wafhttpcore.NormalizeForXSSDetection(v) // S1 二期：叠 HTML 实体/unicode 解码
	if wafhttpcore.IsStructuredDataValue(dv) {    // C：结构化数据(嵌套JSON/URL)不判 XSS
		return false
	}
	return libinjection.IsXSSSingleValue(dv) && reXSSExecSignal.MatchString(dv) // D：多信号
}
