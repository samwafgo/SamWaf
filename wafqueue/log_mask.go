package wafqueue

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// 落库前报文脱敏：event_payload 的 HEADER/COOKIES/ResHeader/POST_FORM 原样落库会把
// Basic 凭据、会话令牌、表单密码留在日志库里；窄行 URL/RawQuery 也要抹，GET 凭证常挂查询串上。
// 脱敏只在副本上做、不改动原始 WebLog 对象；请求体在上游引擎已按同一开关做过 DLP。

// persistSensitiveHeaders 请求侧一律整体脱敏的头。
var persistSensitiveHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
}

// persistSensitiveHeaderKeywords 头名带这些关键字的一律脱敏（自定义鉴权头五花八门，按关键字兜底）。
// 与 wafenginecore/clientip_probe.go 的探针脱敏规则同源，改这里要同步改那边。
var persistSensitiveHeaderKeywords = []string{"token", "secret", "password", "passwd", "credential", "api-key", "apikey", "auth", "session", "signature"}

// persistSensitiveFieldKeywords Cookie/表单字段名带这些关键字的，值一律脱敏。
var persistSensitiveFieldKeywords = []string{"session", "auth", "token", "secret", "passwd", "password", "credential", "key", "sid", "jwt"}

const maskedMarker = "[MASKED]"

func isPersistSensitiveHeader(lowerName string) bool {
	if _, ok := persistSensitiveHeaders[lowerName]; ok {
		return true
	}
	for _, kw := range persistSensitiveHeaderKeywords {
		if strings.Contains(lowerName, kw) {
			return true
		}
	}
	return false
}

func isPersistSensitiveField(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range persistSensitiveFieldKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// maskPersistedHeaderLines 逐行脱敏 joinHeader 拼出的头串（"Name: value\r\n"）。
// res=true 按响应侧规则：只有 Set-Cookie 携带凭据，其余头保留便于排查回源问题。
func maskPersistedHeaderLines(header string, res bool) string {
	if header == "" {
		return ""
	}
	lines := strings.Split(header, "\r\n")
	for i, line := range lines {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(name))
		sensitive := lower == "set-cookie"
		if !res {
			sensitive = isPersistSensitiveHeader(lower)
		}
		if sensitive {
			lines[i] = name + ": " + maskedMarker
		}
	}
	return strings.Join(lines, "\r\n")
}

// maskPersistedCookies COOKIES 列是 r.Cookies() 的 JSON 数组，按 cookie 名脱敏值。
// JSON 解析失败原样返回：值此时已在 HEADER 的 Cookie 行里被抹掉，不再二次处理。
func maskPersistedCookies(cookies string) string {
	if cookies == "" {
		return ""
	}
	var list []http.Cookie
	if err := json.Unmarshal([]byte(cookies), &list); err != nil {
		return cookies
	}
	changed := false
	for i := range list {
		if isPersistSensitiveField(list[i].Name) {
			list[i].Value = maskedMarker
			changed = true
		}
	}
	if !changed {
		return cookies
	}
	out, err := json.Marshal(list)
	if err != nil {
		return cookies
	}
	return string(out)
}

// maskPersistedForm 表单编码串按字段名脱敏（登录表单密码等）。
func maskPersistedForm(form string) string {
	if form == "" {
		return ""
	}
	parts := strings.Split(form, "&")
	for i, part := range parts {
		name, _, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if isPersistSensitiveField(name) {
			parts[i] = name + "=" + maskedMarker
		}
	}
	return strings.Join(parts, "&")
}

// maskPersistedQuery 查询串按参数名脱敏（GET 请求的凭证常挂在 ?api_key= 上）。
// RawQuery 入库前已做多轮解码，参数名一般是明文；残留编码再解一次做判定。
func maskPersistedQuery(query string) string {
	if query == "" {
		return ""
	}
	parts := strings.Split(query, "&")
	for i, part := range parts {
		name, _, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		check := name
		if dec, err := url.QueryUnescape(name); err == nil {
			check = dec
		}
		if isPersistSensitiveField(check) {
			parts[i] = name + "=" + maskedMarker
		}
	}
	return strings.Join(parts, "&")
}

// maskPersistedRequestURI 只抹 ? 后的查询串，路径不动（路径做关键字匹配误伤太大）。
func maskPersistedRequestURI(uri string) string {
	path, query, found := strings.Cut(uri, "?")
	if !found {
		return uri
	}
	return path + "?" + maskPersistedQuery(query)
}
