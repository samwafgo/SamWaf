package libinjection

import (
	"SamWaf/innerbean"
	"testing"
)

func mkUA(s string) *innerbean.WebLog  { return &innerbean.WebLog{USER_AGENT: s} }
func mkURL(s string) *innerbean.WebLog { return &innerbean.WebLog{URL: s} }

func TestIsScan_Detects(t *testing.T) {
	cases := []*innerbean.WebLog{
		mkUA("sqlmap/1.8.3#stable (https://sqlmap.org)"),
		mkUA("Mozilla/5.00 (Nikto/2.5.0)"),
		mkUA("Mozilla/5.0 (compatible; Nmap Scripting Engine)"), // UA-only 词
		mkUA("masscan/1.3"),
		mkUA("WPScan v3.8.24"),
		mkUA("gobuster/3.6"),
		mkUA("DirBuster-1.0-RC1"),
		mkURL("/x?f=acunetix_wvs_security_test"), // URL 里的独特指纹
	}
	for _, c := range cases {
		if !IsScan(c) {
			t.Errorf("应判定为扫描器但漏过: URL=%q UA=%q", c.URL, c.USER_AGENT)
		}
	}
}

func TestIsScan_NoFalsePositive(t *testing.T) {
	cases := []*innerbean.WebLog{
		mkUA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"),
		mkUA("curl/7.68.0"),                         // 常见但不必然恶意，不拦
		mkUA("python-requests/2.31"),                // 同上
		mkURL("/blog?topic=cell-nuclei-in-biology"), // nuclei 是 UA-only，不在 URL 里判
		mkURL("/shop?category=arachnid-figures"),    // arachni 是 UA-only
		mkUA("Googlebot/2.1 (+http://www.google.com/bot.html)"),
	}
	for _, c := range cases {
		if IsScan(c) {
			t.Errorf("正常请求被误判为扫描器: URL=%q UA=%q", c.URL, c.USER_AGENT)
		}
	}
}
