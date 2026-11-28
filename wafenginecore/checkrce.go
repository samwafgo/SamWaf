package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafdefenserce"
	"SamWaf/wafenginecore/wafhttpcore"
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
	ensureWebLogBodyClassified(r, weblogbean, &formValue)

	// multipart 与确认二进制体不把文件原始字节整块送入命令检测（multipart 文本字段走下方 formValue/BodyValues）
	rawBody := weblogbean.BODY
	if weblogbean.IsMultipart || weblogbean.IsBinaryBody {
		rawBody = ""
	}

	// 既有检测（查询串多轮解码 + 原始 cookie/非二进制body + 逐个表单字段）：始终强制拦截
	isRce, RceName := wafdefenserce.DetermineRCE(weblogbean.RawQuery, weblogbean.URL,
		weblogbean.COOKIES, rawBody)
	if !isRce {
		for key, values := range formValue {
			if isBodyFieldExcluded(key) { // E
				continue
			}
			if ok, name := wafdefenserce.DetermineRCE(wafhttpcore.NormalizeForDetection(key)); ok {
				isRce, RceName = ok, name
				break
			}
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
	if !isRce && len(weblogbean.MultipartPlainFiles) > 0 {
		for _, pf := range weblogbean.MultipartPlainFiles {
			if ok, name := wafdefenserce.DetermineRCE(pf); ok {
				isRce, RceName = ok, name
				break
			}
		}
	}
	if isRce {
		weblogbean.RISK_LEVEL = 3
		result.IsBlock = true
		result.Title = "RCE:" + RceName
		result.Content = "请正确访问"
		return result
	}
	// 请求体深度检测（S1 新增：cookie/body 解码副本 + JSON 逐值）：受 body_detect_mode 门控
	if bodyDetectEnabled() {
		decodedBody := weblogbean.BodyDecoded
		if weblogbean.IsMultipart || weblogbean.IsBinaryBody {
			decodedBody = ""
		}
		hit, name := wafdefenserce.DetermineRCE(weblogbean.CookiesDecoded, decodedBody)
		if !hit {
			for i, v := range weblogbean.BodyValues {
				if isBodyFieldExcluded(fieldAt(weblogbean.BodyFields, i)) { // E
					continue
				}
				if ok, n := wafdefenserce.DetermineRCE(v); ok {
					hit, name = ok, n
					break
				}
			}
		}
		if !hit { // 头位命令注入(S1-4)
			hit, name = headerRCEHit(r)
		}
		if hit {
			if bodyDetectBlocking() {
				weblogbean.RISK_LEVEL = 3
				result.IsBlock = true
				result.Title = "RCE:" + name
				result.Content = "请正确访问"
				return result
			}
			markBodyObserve(weblogbean, "RCE:"+name)
		}
	}
	return result
}
