package libinjection

import (
	"net/url"

	"github.com/corazawaf/libinjection-go"
)

func IsXSS(input string) bool {
	return libinjection.IsXSS(input)
}

func IsSQLiNotReturnPrint(input string) bool {
	result, _ := libinjection.IsSQLi(input)
	return result
}

// containsXSSChars 快速判断字符串是否包含 XSS 攻击的必要字符。
// 真实 XSS payload 必须含有 HTML/JS 特殊字符；不含这些字符可直接跳过 libinjection。
func containsXSSChars(s string) bool {
	for _, c := range s {
		switch c {
		case '<', '>', '"', '\'', '(', ')', '/', '`':
			return true
		}
	}
	return false
}

// IsXSSSingleValue 对单个已解码的参数值进行 XSS 检测，先做快速预过滤再调用 libinjection。
// 适用于已经拆分好的单个表单字段值。
func IsXSSSingleValue(v string) bool {
	return containsXSSChars(v) && libinjection.IsXSS(v)
}

// IsXSSInQueryValues 解析 query string，仅对参数值调用 IsXSS，避免参数名（如 style、href）
// 被 libinjection 误当 HTML 属性导致误报。
// 解析失败时回退到对整体字符串做预过滤 + IsXSS 检测。
func IsXSSInQueryValues(query string) bool {
	if query == "" {
		return false
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		// 解析失败说明格式异常，可能是恶意构造，回退到整体检测
		return containsXSSChars(query) && libinjection.IsXSS(query)
	}
	for _, vals := range values {
		for _, v := range vals {
			if IsXSSSingleValue(v) {
				return true
			}
		}
	}
	return false
}
