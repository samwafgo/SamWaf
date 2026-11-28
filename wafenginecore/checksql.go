package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/innerbean"
	"SamWaf/libinjection-go"
	"SamWaf/model/detection"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/wafhttpcore"
	"go.uber.org/zap"
	"net/http"
	"net/url"
)

func matchSQLiByLibinjection(input, reqUUID string) bool {
	if input == "" {
		return false
	}
	ok, fp := libinjection.IsSQLiInspect(input)
	if ok {
		zlog.Debug("CheckSql matched fingerprint", zap.String("fp", fp), zap.String("req_uuid", reqUUID))
	}
	return ok
}

func matchFieldSQLi(v, reqUUID string) bool {
	if v == "" {
		return false
	}
	if wafhttpcore.HasHighRiskSQLKeyword(v) { // 高危关键字：不跳过结构化
		return true
	}
	// 跳过结构化数据值（嵌套 JSON/回调 URL）：正常埋点/日志会误报，且不构成 SQLi
	if wafhttpcore.IsStructuredDataValue(v) {
		return false
	}
	return matchSQLiByLibinjection(v, reqUUID)
}

// isSimpleFormFieldKey 判断表单键名是否为标准标识符（仅含字母、数字、_、-、.、[]）。
// 标准参数名下的正常英文散文（如 title="hello" and world）若拼成 title="hello" and world 会击穿
// libinjection 的 3-Token 散文白名单误报 nos&n；仅当键名本身含空格/引号/括号等异常字符（即无参数名前缀的
// 裸注入串 "' OR '1'='1" 被首个 "=" 切碎）时才需要拼回 dk+"="+v 复检。
func isSimpleFormFieldKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlphaNum && c != '_' && c != '-' && c != '.' && c != '[' && c != ']' {
			return false
		}
	}
	return true
}

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
	ensureWebLogBodyClassified(r, weblogbean, &formValue)

	var sqlFlag = false
	// 1) 查询串、已解析表单参数（urlencoded 及合法 multipart 的非文件字段与元数据）、
	//    以及存在协议头歧义/畸形的请求体（多 Content-Type / 畸形 multipart / 畸形 urlencoded）：始终强制拦截
	if matchSQLiByLibinjection(weblogbean.RawQuery, weblogbean.REQ_UUID) ||
		matchSQLiByLibinjection(weblogbean.POST_FORM, weblogbean.REQ_UUID) ||
		wafhttpcore.HasHighRiskSQLKeyword(weblogbean.RawQuery) ||
		wafhttpcore.HasHighRiskSQLKeyword(weblogbean.POST_FORM) {
		sqlFlag = true
	}
	if !sqlFlag && weblogbean.HasAmbiguousBodyType && !weblogbean.IsBinaryBody {
		if wafhttpcore.HasHighRiskSQLKeyword(weblogbean.BODY) ||
			matchSQLiByLibinjection(weblogbean.BODY, weblogbean.REQ_UUID) ||
			matchSQLiByLibinjection(weblogbean.BodyDecoded, weblogbean.REQ_UUID) {
			sqlFlag = true
		}
	}
	if !sqlFlag {
		for key, value := range formValue {
			if isBodyFieldExcluded(key) { // E：已知富文本字段整体跳过
				continue
			}
			dk := wafhttpcore.NormalizeForDetection(key)
			// 兼顾无 "=" 的裸表单串与参数名注入
			if matchFieldSQLi(dk, weblogbean.REQ_UUID) {
				sqlFlag = true
				break
			}
			for _, v := range value {
				if matchFieldSQLi(v, weblogbean.REQ_UUID) {
					sqlFlag = true
					break
				}
				// urlencoded 无参数名前缀时（如裸发 "' OR '1'='1"），ParseQuery 按首个 "=" 切分
				// 会将注入表达式拆到非标识符 key 与 v 两半；仅对非标准键名拼回复检，避免正常字段名破坏 3-Token 白名单。
				if weblogbean.IsUrlEncodedForm && !isSimpleFormFieldKey(dk) && v != "" && !wafhttpcore.IsStructuredDataValue(v) {
					if matchSQLiByLibinjection(dk+"="+v, weblogbean.REQ_UUID) {
						sqlFlag = true
						break
					}
				}
			}
			if sqlFlag {
				break
			}
		}
	}
	if sqlFlag {
		weblogbean.RISK_LEVEL = 2
		result.IsBlock = true
		result.Title = "SQL注入"
		result.Content = "请正确访问"
		return result
	}

	// 2) 请求体深检（JSON 逐值 / 自定义头 / 未知裸文本 BODY）：统一受 body_detect_mode 门控。
	//    结构合法的 multipart（文件字节归 CheckUpload、文本字段已在上方 formValue 检测）、
	//    已确认的二进制体（image/octet-stream 等）、已解析的 urlencoded 与合法 JSON 均不再整块扫原始 BODY。
	if bodyDetectEnabled() {
		hit := false
		scanRawTextBody := weblogbean.BODY != "" &&
			!weblogbean.IsMultipart &&
			!weblogbean.IsBinaryBody &&
			!weblogbean.IsUrlEncodedForm &&
			!wafhttpcore.IsJSONBody(weblogbean.BODY)

		if scanRawTextBody {
			if wafhttpcore.HasHighRiskSQLKeyword(weblogbean.BODY) ||
				matchSQLiByLibinjection(weblogbean.BODY, weblogbean.REQ_UUID) {
				hit = true
			}
		}
		if !hit {
			for i, v := range weblogbean.BodyValues {
				if isBodyFieldExcluded(fieldAt(weblogbean.BodyFields, i)) {
					continue
				}
				if matchFieldSQLi(v, weblogbean.REQ_UUID) {
					hit = true
					break
				}
			}
		}
		if !hit { // 头位 SQLi(S1-4)
			hit = headerSQLHit(r)
		}
		if hit {
			if bodyDetectBlocking() {
				weblogbean.RISK_LEVEL = 2
				result.IsBlock = true
				result.Title = "SQL注入"
				result.Content = "请正确访问"
				return result
			}
			markBodyObserve(weblogbean, "SQL注入")
		}
	}
	return result
}
