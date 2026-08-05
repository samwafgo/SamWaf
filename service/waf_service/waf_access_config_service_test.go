package waf_service

import "testing"

// TestBuildOrigin 锁死认证中心候选地址的拼法。
//
// 这里唯一容易出错、也唯一有后果的点是「默认端口要不要写出来」：
// 引擎侧比对认证中心域名时用的是请求里的 Host 头，而浏览器在 443/80 上
// 根本不会带端口。生成成 https://sso.a.com:443 的话，比对必然不相等，
// 表现是配好了 SSO 却一直跳不过去——而且完全没有报错，极难排查。
func TestBuildOrigin(t *testing.T) {
	cases := []struct {
		domain string
		port   int
		ssl    bool
		want   string
	}{
		{"sso.example.com", 443, true, "https://sso.example.com"},
		{"sso.example.com", 80, false, "http://sso.example.com"},
		{"sso.example.com", 8443, true, "https://sso.example.com:8443"},
		{"sso.example.com", 8080, false, "http://sso.example.com:8080"},
		// 端口没填时按协议默认端口处理，不能拼出 ":0"
		{"sso.example.com", 0, true, "https://sso.example.com"},
	}
	for _, c := range cases {
		if got := buildOrigin(c.domain, c.port, c.ssl); got != c.want {
			t.Errorf("buildOrigin(%q,%d,%v)=%q, want %q", c.domain, c.port, c.ssl, got, c.want)
		}
	}
}

// TestNormalizeCenterOriginRoundTrip 保证「下拉里选出来的地址」保存时不会被改写。
// 候选列表由 buildOrigin 生成，若两者对同一个站点给出不同结果，
// 用户会看到自己选的值保存后变了样。
func TestNormalizeCenterOriginRoundTrip(t *testing.T) {
	for _, in := range []string{
		"https://sso.example.com",
		"http://sso.example.com",
		"https://sso.example.com:8443",
	} {
		origin, host, err := normalizeCenterOrigin(in)
		if err != nil {
			t.Fatalf("normalizeCenterOrigin(%q) err=%v", in, err)
		}
		if origin != in {
			t.Errorf("normalizeCenterOrigin(%q) origin=%q, want unchanged", in, origin)
		}
		if host == "" {
			t.Errorf("normalizeCenterOrigin(%q) host empty", in)
		}
	}
}
