package wafqueue

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"strings"
	"testing"
)

// webdavLog 复刻 issue #1050 场景：WebDAV Basic 认证请求。
// 敏感值统一带字母 n，命中旧展示层正则的断尾盲区。
func webdavLog() *innerbean.WebLog {
	return &innerbean.WebLog{
		REQ_UUID:  "mask-1",
		HOST_CODE: "h1",
		USER_CODE: "u1",
		URL:       "/dav/files?api_key=9n8kss&path=/x",
		RawQuery:  "api_key=9n8kss&path=%2Fx",
		HEADER: "Host: xxxx.com\r\n" +
			"Authorization: Basic dXNlcjpwYXNzd29yZA0K\r\n" + // base64(用户:密码)，含 n
			"X-Custom-Token: tok3nvalue\r\n" +
			"User-Agent: curl\r\n",
		COOKIES:  `[{"name":"sessionid","value":"sessi0nvalue"},{"name":"theme","value":"dark"}]`,
		POST_FORM: "username=alice&password=p4ssw0rd&page=1",
		ResHeader: "HTTP/1.1 401 Unauthorized\r\n" +
			"WWW-Authenticate: Basic realm=\"WebDAV\"\r\n" +
			"Set-Cookie: sessionid=abc123; Path=/\r\n",
		Day:       20261105,
		SrcURL:    []byte("/dav/files?api_key=9n8kss&path=/x"),
	}
}

func TestExtractPayloadMasksCredentials(t *testing.T) {
	old := global.GCONFIG_RECORD_LOG_DESENSITIZE
	global.GCONFIG_RECORD_LOG_DESENSITIZE = 1
	defer func() { global.GCONFIG_RECORD_LOG_DESENSITIZE = old }()

	lg := webdavLog()
	rawHeader := lg.HEADER
	p := extractPayload(lg, PayloadKindEvent)
	if p == nil {
		t.Fatal("报文不应为空")
	}

	// 敏感头整体抹掉
	for _, secret := range []string{"dXNlcjpwYXNzd29yZA0K", "tok3nvalue"} {
		if strings.Contains(p.HEADER, secret) {
			t.Fatalf("HEADER 仍含明文凭证 %q: %q", secret, p.HEADER)
		}
	}
	if !strings.Contains(p.HEADER, "Authorization: [MASKED]") ||
		!strings.Contains(p.HEADER, "X-Custom-Token: [MASKED]") {
		t.Fatalf("敏感头未脱敏: %q", p.HEADER)
	}
	// 非敏感头保留
	if !strings.Contains(p.HEADER, "User-Agent: curl") || !strings.Contains(p.HEADER, "Host: xxxx.com") {
		t.Fatalf("非敏感头不应被动过: %q", p.HEADER)
	}

	// Cookie：敏感名脱敏、普通名保留
	if strings.Contains(p.COOKIES, "sessi0nvalue") || !strings.Contains(p.COOKIES, maskedMarker) {
		t.Fatalf("敏感 Cookie 未脱敏: %q", p.COOKIES)
	}
	if !strings.Contains(p.COOKIES, "dark") {
		t.Fatalf("普通 Cookie 不应被脱敏: %q", p.COOKIES)
	}

	// 表单：密码脱敏、其他字段保留
	if strings.Contains(p.POST_FORM, "p4ssw0rd") || !strings.Contains(p.POST_FORM, "password="+maskedMarker) {
		t.Fatalf("表单密码未脱敏: %q", p.POST_FORM)
	}
	// 查询串：敏感参数抹值、普通参数保留（窄行 URL/RawQuery 与报文 SrcURL 同规则）
	if !strings.Contains(p.POST_FORM, "username=alice") {
		t.Fatalf("普通表单字段不应被脱敏: %q", p.POST_FORM)
	}
	if strings.Contains(string(p.SrcURL), "9n8kss") ||
		!strings.Contains(string(p.SrcURL), "api_key="+maskedMarker) ||
		!strings.Contains(string(p.SrcURL), "path=/x") {
		t.Fatalf("SrcURL 查询串脱敏不对: %q", p.SrcURL)
	}

	// 响应头：Set-Cookie 脱敏，WWW-Authenticate realm 保留（排查认证流程要用）
	if strings.Contains(p.ResHeader, "abc123") || !strings.Contains(p.ResHeader, "Set-Cookie: [MASKED]") {
		t.Fatalf("Set-Cookie 未脱敏: %q", p.ResHeader)
	}
	if !strings.Contains(p.ResHeader, `WWW-Authenticate: Basic realm="WebDAV"`) {
		t.Fatalf("WWW-Authenticate 不应被脱敏: %q", p.ResHeader)
	}

	// 脱敏只作用于副本：原对象仍是完整报文（检测/出口要用）
	if lg.HEADER != rawHeader || !strings.Contains(lg.HEADER, "dXNlcjpwYXNzd29yZA0K") {
		t.Fatal("extractPayload 不应改动原始 WebLog")
	}
}

func TestExtractPayloadMaskDisabledStoresRaw(t *testing.T) {
	old := global.GCONFIG_RECORD_LOG_DESENSITIZE
	global.GCONFIG_RECORD_LOG_DESENSITIZE = 0
	defer func() { global.GCONFIG_RECORD_LOG_DESENSITIZE = old }()

	p := extractPayload(webdavLog(), PayloadKindEvent)
	if p == nil {
		t.Fatal("报文不应为空")
	}
	if !strings.Contains(p.HEADER, "dXNlcjpwYXNzd29yZA0K") {
		t.Fatalf("开关关闭时应原样落库: %q", p.HEADER)
	}
}

// TestExtractPayloadMaskNotTruncated 脱敏缩短内容不得误标 Truncated。
func TestExtractPayloadMaskNotTruncated(t *testing.T) {
	old := global.GCONFIG_RECORD_LOG_DESENSITIZE
	global.GCONFIG_RECORD_LOG_DESENSITIZE = 1
	defer func() { global.GCONFIG_RECORD_LOG_DESENSITIZE = old }()

	p := extractPayload(webdavLog(), PayloadKindEvent)
	if p.Truncated != 0 {
		t.Fatalf("脱敏不等于截断，Truncated 应为 0，实际 %d", p.Truncated)
	}
}

// TestNarrowMasksQueryCredentials 窄行 URL/RawQuery 的查询串凭证同样落库前抹掉。
func TestNarrowMasksQueryCredentials(t *testing.T) {
	old := global.GCONFIG_RECORD_LOG_DESENSITIZE
	global.GCONFIG_RECORD_LOG_DESENSITIZE = 1
	defer func() { global.GCONFIG_RECORD_LOG_DESENSITIZE = old }()

	ln := narrowFromLog(webdavLog())
	if strings.Contains(ln.URL, "9n8kss") || !strings.Contains(ln.URL, "api_key="+maskedMarker) {
		t.Fatalf("窄行 URL 查询串未脱敏: %q", ln.URL)
	}
	if strings.Contains(ln.RawQuery, "9n8kss") || !strings.Contains(ln.RawQuery, "api_key="+maskedMarker) ||
		!strings.Contains(ln.RawQuery, "path=%2Fx") {
		t.Fatalf("窄行 RawQuery 未脱敏: %q", ln.RawQuery)
	}
	if ln.Truncated != 0 {
		t.Fatalf("脱敏不等于截断，Truncated 应为 0，实际 %d", ln.Truncated)
	}

	global.GCONFIG_RECORD_LOG_DESENSITIZE = 0
	ln = narrowFromLog(webdavLog())
	if !strings.Contains(ln.URL, "9n8kss") {
		t.Fatalf("开关关闭时窄行应原样落库: %q", ln.URL)
	}
}
