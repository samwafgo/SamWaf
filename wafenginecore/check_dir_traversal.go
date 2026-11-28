package wafenginecore

import (
	"SamWaf/innerbean"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/wafhttpcore"
	"net/http"
	"net/url"
)

// CheckDirTraversal 目录穿越 / 绝对路径 LFI 检测(D4+D6)。
// 归一化后判"逃出根"而非字面 ../，并叠敏感文件表接住裸绝对路径；站内相对路径不误拦。
func (waf *WafEngine) CheckDirTraversal(r *http.Request, weblogbean *innerbean.WebLog, formValue url.Values, hostTarget *wafenginmodel.HostSafe, globalHostTarget *wafenginmodel.HostSafe) detection.Result {
	result := detection.Result{
		JumpGuardResult: false,
		IsBlock:         false,
		Title:           "",
		Content:         "",
	}
	ensureWebLogBodyClassified(r, weblogbean, &formValue)

	block := func() detection.Result {
		weblogbean.RISK_LEVEL = 2
		result.IsBlock = true
		result.Title = "目录穿越漏洞"
		result.Content = "请正确访问"
		return result
	}

	// 1) 始终检测：URL 路径 + 查询值(逃根判定+敏感文件，低误报，非请求体不受开关影响)
	if wafhttpcore.HasTraversalOrLFI(r.URL.EscapedPath()) {
		return block()
	}
	for _, values := range r.URL.Query() {
		for _, v := range values {
			if wafhttpcore.HasTraversalOrLFI(v) {
				return block()
			}
		}
	}

	// 2) 请求体深检(表单值/JSON 体/非二进制整串)：受 body_detect_mode 门控(observe 默认只观察不拦)，与 CheckXss 一致
	if bodyDetectEnabled() {
		hit := false
		if !weblogbean.IsMultipart && !weblogbean.IsBinaryBody {
			hit = wafhttpcore.HasTraversalOrLFI(weblogbean.BodyDecoded)
		}
		if !hit {
			for key, values := range formValue {
				if isBodyFieldExcluded(key) { // E：已知富文本字段整体跳过
					continue
				}
				if wafhttpcore.HasTraversalOrLFI(wafhttpcore.NormalizeForDetection(key)) {
					hit = true
					break
				}
				for _, v := range values {
					if wafhttpcore.HasTraversalOrLFI(v) {
						hit = true
						break
					}
				}
				if hit {
					break
				}
			}
		}
		if !hit {
			for i, v := range weblogbean.BodyValues {
				if isBodyFieldExcluded(fieldAt(weblogbean.BodyFields, i)) { // E
					continue
				}
				if wafhttpcore.HasTraversalOrLFI(v) {
					hit = true
					break
				}
			}
		}
		if hit {
			if bodyDetectBlocking() {
				return block()
			}
			markBodyObserve(weblogbean, "目录穿越/LFI")
		}
	}

	return result
}
