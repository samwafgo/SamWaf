package waf_service

import (
	"net/url"
	"testing"
)

func TestExtractTamperCandidates(t *testing.T) {
	htmlContent := []byte(`
<html><head>
<link rel="stylesheet" href="/css/app.css">
<link rel="icon" href="favicon.ico">
<script src="/js/app.js?v=123"></script>
<script src="https://example.com/js/vendor.js"></script>
<script src="https://cdn.other.com/lib.js"></script>
</head><body>
<img src="/img/logo.png">
<img src="images/banner.jpg">
<a href="/about.html">about</a>
<a href="https://example.com/contact.html">contact</a>
<a href="https://third.com/x.html">ext</a>
<a href="#top">anchor</a>
<a href="javascript:void(0)">js</a>
<a href="mailto:a@b.com">mail</a>
<script src="/js/app.js"></script>
</body></html>`)
	siteBase, _ := url.Parse("https://example.com/")
	siteHosts := map[string]bool{"example.com": true}
	got := extractTamperCandidates(htmlContent, siteBase, siteHosts)

	types := map[string]string{}
	for _, d := range got {
		types[d.Url] = d.Type
	}

	// 同站资源应提取，且类型正确
	wantKeep := map[string]string{
		"/css/app.css":       "css",
		"/favicon.ico":       "img",
		"/js/app.js":         "js", // 带 ?v=123 去参后与末尾无参项去重为一条
		"/js/vendor.js":      "js", // 站点绝对地址
		"/img/logo.png":      "img",
		"/images/banner.jpg": "img",
		"/about.html":        "html",
		"/contact.html":      "html",
	}
	for u, ty := range wantKeep {
		if types[u] != ty {
			t.Errorf("应提取 %s(type=%s)，实际 type=%q", u, ty, types[u])
		}
	}

	// 第三方资源应丢弃（不同 host）
	if _, ok := types["/lib.js"]; ok {
		t.Errorf("第三方 cdn.other.com/lib.js 不应被提取")
	}
	if _, ok := types["/x.html"]; ok {
		t.Errorf("第三方 third.com/x.html 不应被提取")
	}

	// 去重 + data/js/mailto/anchor 均无有效 path → 总数应为 8
	if len(got) != 8 {
		t.Errorf("应提取 8 条同站候选，实际 %d 条: %+v", len(got), got)
	}
}

func TestExtractPathOnly(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/index.html", "/index.html"},
		{"index.html", "/index.html"},
		{"https://example.com/a/b.html?x=1#f", "/a/b.html"},
		{"http://1.2.3.4:8080/app.js", "/app.js"},
		{"/p?q=1", "/p"},
	}
	for _, c := range cases {
		if got := extractPathOnly(c.in); got != c.want {
			t.Errorf("extractPathOnly(%q)=%q, 期望 %q", c.in, got, c.want)
		}
	}
}

func TestPickExtractDomain(t *testing.T) {
	siteHosts := map[string]bool{"example.com": true, "www.example.com": true}
	cases := []struct {
		name string
		req  string
		want string
	}{
		{"属于本站直接用", "www.example.com", "www.example.com"},
		{"大写归一化匹配", "WWW.Example.com", "www.example.com"},
		{"带端口去端口匹配", "example.com:8443", "example.com"},
		{"非本站回退主域名", "evil.com", "example.com"},
		{"空回退主域名", "", "example.com"},
	}
	for _, c := range cases {
		if got := pickExtractDomain(c.req, siteHosts, "example.com"); got != c.want {
			t.Errorf("%s: pickExtractDomain(%q)=%q, 期望 %q", c.name, c.req, got, c.want)
		}
	}
}

func TestSha256HexSvc(t *testing.T) {
	a := sha256HexSvc([]byte("hello"))
	b := sha256HexSvc([]byte("hello"))
	c := sha256HexSvc([]byte("world"))
	if a != b {
		t.Errorf("相同内容哈希应一致")
	}
	if a == c {
		t.Errorf("不同内容哈希应不同")
	}
	if len(a) != 64 {
		t.Errorf("sha256 十六进制应为64字符，实际 %d", len(a))
	}
}
