package wafhttpcore

import (
	"encoding/json"
	"html"
	"regexp"
	"strconv"
	"strings"
)

// NormalizeForDetection 供检测使用的归一化：多轮 URL 解码（含 PHP 兜底）。
// 原文另存用于落库/展示，这里只产出喂给各 check 的解码副本，覆盖 body/cookie/
// 表单值里的（多层）URL 编码绕过（S1）。
func NormalizeForDetection(raw string) string {
	if raw == "" {
		return ""
	}
	return WafHttpCoreUrlEncode(raw, 10)
}

const (
	maxJSONBodyForDetection   = 512 * 1024 // 超过则不做 JSON 逐值提取，避免大体积开销
	maxJSONValuesForDetection = 2000       // 值数量上限，防深/宽 JSON 撑爆
)

// reJSEscape 匹配 JS/JSON unicode/hex 转义：\uXXXX、\u{XX..}、\xXX。
var reJSEscape = regexp.MustCompile(`\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})`)

// decodeJSEscapes 把 \uXXXX/\u{..}/\xXX 还原为字符（覆盖 unicode_js 编码变体）。
func decodeJSEscapes(s string) string {
	if !strings.Contains(s, `\u`) && !strings.Contains(s, `\x`) {
		return s
	}
	return reJSEscape.ReplaceAllStringFunc(s, func(m string) string {
		hex := ""
		for _, g := range reJSEscape.FindStringSubmatch(m)[1:] {
			if g != "" {
				hex = g
				break
			}
		}
		n, err := strconv.ParseInt(hex, 16, 32)
		if err != nil || n < 0 || n > 0x10FFFF {
			return m
		}
		return string(rune(n))
	})
}

// NormalizeForXSSDetection 在 URL 解码基础上再叠 HTML 实体解码 + JS unicode/hex 转义解码（S1 二期）。
// 仅用于 XSS 检测路径——htmlent(&lt;/&#40;)、unicode_js(<) 编码的 XSS 解开后才能被 libinjection
// 认出。因解码会放大误报面，仅配合"多信号(真标签/事件)"使用，且不作用于 SQLi/RCE。
func NormalizeForXSSDetection(raw string) string {
	if raw == "" {
		return ""
	}
	s := NormalizeForDetection(raw) // 多轮 URL 解码
	s = html.UnescapeString(s)      // HTML 实体：&lt; &gt; &quot; &#39; &#40; &#x3c;
	s = decodeJSEscapes(s)          // JS 转义：< \x3c
	return s
}

// ExtractJSONFieldValues 把 JSON 请求体里的所有字符串**值**逐个取出，并返回每个值的**直接父键名**
// (fields[i] 对应 values[i]；顶层数组元素父键为 "")。相比“整块 body 喂 libinjection”，逐值能大幅
// 降误报（数字/布尔/结构字符不参与），且 json 解析天然解掉 \uXXXX 转义（覆盖 {"x":"<script>"} 绕过）。
// 携带字段名是为了支持“按字段排除”(E)：已知装富文本/HTML 的字段可整体跳过深检。
// 注意：不再对取出的值额外做 URL 解码——URL 编码的 JSON 值解开后会变回 JSON 结构被误判。
// 非 JSON / 空 / 超限返回 nil,nil。
func ExtractJSONFieldValues(body string) (fields, values []string) {
	fields, values, _ = ExtractJSONFieldValuesComplete(body)
	return fields, values
}

// ExtractJSONFieldValuesComplete 与 ExtractJSONFieldValues 相同，但额外返回 complete 指示是否完整提取了所有字符串叶节点
// （未因超体积上限、解析错误或超 2000 值上限而提前截断）。
func ExtractJSONFieldValuesComplete(body string) (fields, values []string, complete bool) {
	s := strings.TrimSpace(body)
	if len(s) == 0 || len(s) > maxJSONBodyForDetection {
		return nil, nil, false
	}
	if s[0] != '{' && s[0] != '[' {
		return nil, nil, false
	}
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, nil, false // 非合法 JSON：正常非 JSON 体不参与，避免误报
	}
	capped := false
	var walk func(field string, x interface{})
	walk = func(field string, x interface{}) {
		if len(values) >= maxJSONValuesForDetection {
			capped = true
			return
		}
		switch t := x.(type) {
		case string:
			fields = append(fields, field)
			values = append(values, t)
		case []interface{}:
			for _, e := range t {
				walk(field, e) // 数组元素继承父键名
			}
		case map[string]interface{}:
			for k, e := range t { // 进入 map，键名成为子值的 field（只取值不取键名）
				walk(k, e)
			}
		}
	}
	walk("", v)
	return fields, values, !capped
}

// ExtractJSONStringValues 仅取值（向后兼容）。
func ExtractJSONStringValues(body string) []string {
	_, values := ExtractJSONFieldValues(body)
	return values
}

// IsJSONBody 报告 body 是否为合法 JSON 对象/数组。用于 SQLi：JSON 体走逐值检测即可，
// 不再整块喂 libinjection（整块含大量 , : " { } 结构字符，正常数字/结构 JSON 会被误判）。
func IsJSONBody(body string) bool {
	s := strings.TrimSpace(body)
	if len(s) == 0 || len(s) > maxJSONBodyForDetection {
		return false
	}
	if s[0] != '{' && s[0] != '[' {
		return false
	}
	return json.Valid([]byte(s))
}

// IsStructuredDataValue 报告值更像“结构化数据”而非 SQL 注入串：JSON 对象/数组、或 http(s)
// URL。对这类值跳过 SQLi 逐值检测——正常埋点/日志/回调常把嵌套 JSON、回调 URL 塞进字段值，
// libinjection 会把其中的引号/逗号/短横线误判为 SQLi。仅作用于 SQLi，不影响 XSS/RCE。
func IsStructuredDataValue(v string) bool {
	s := strings.TrimSpace(v)
	if s == "" {
		return false
	}
	if s[0] == '{' || s[0] == '[' {
		return true
	}
	ls := strings.ToLower(s)
	return strings.HasPrefix(ls, "http://") || strings.HasPrefix(ls, "https://")
}
