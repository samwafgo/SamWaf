package api

import (
	"strings"
	"testing"
)

// TestMaskSensitiveHeaderNoTailLeak 值里带字母 n 时不得断尾泄密：
// 旧正则 [^\\n] 在反引号串里排除的是反斜杠与字母 n，匹配到值里第一个 n 就停。
func TestMaskSensitiveHeaderNoTailLeak(t *testing.T) {
	header := "Host: xxxx.com\r\n" +
		"Authorization: Bearer ndsj7llhjnc\r\n" + // 值以 n 开头、中间含 n
		"X-Api-Key: ab3n9xyz\r\n" +
		"User-Agent: curl\r\n"

	masked := maskSensitiveHeader(header)
	for _, secret := range []string{"ndsj7llhjnc", "ab3n9xyz"} {
		if strings.Contains(masked, secret) {
			t.Fatalf("值未完整脱敏，断尾残留 %q: %q", secret, masked)
		}
	}
	if !strings.Contains(masked, "Authorization: [MASKED]") ||
		!strings.Contains(masked, "X-Api-Key: [MASKED]") {
		t.Fatalf("敏感头未脱敏: %q", masked)
	}
	if !strings.Contains(masked, "User-Agent: curl") {
		t.Fatalf("非敏感头不应被动过: %q", masked)
	}
}

// TestMaskSensitiveCookiesJSON COOKIES 列是 http.Cookie 的 JSON 数组，
// 展示层必须按名脱敏值（历史数据兜底，新数据落库时已脱敏）。
func TestMaskSensitiveCookiesJSON(t *testing.T) {
	cookies := `[{"name":"sessionid","value":"sessi0nvalue"},{"name":"theme","value":"dark"}]`
	masked := maskSensitiveCookies(cookies)
	if strings.Contains(masked, "sessi0nvalue") || !strings.Contains(masked, "[MASKED]") {
		t.Fatalf("JSON Cookie 未脱敏: %q", masked)
	}
	if !strings.Contains(masked, "dark") {
		t.Fatalf("普通 Cookie 不应被脱敏: %q", masked)
	}
}
