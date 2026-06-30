package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func TestCheckCsrf(t *testing.T) {
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "json")
	waf := &WafEngine{}
	waf.InitRouting()

	// 构造一个站点配置生成器：默认开启、保护 POST/PUT/DELETE/PATCH，绑定 alias.com，额外允许 trusted.com 与 *.partner.com
	buildHost := func(allowEmptyRef int, excludePaths string) *wafenginmodel.HostSafe {
		cfg := model.CsrfConfig{
			IsEnable:       1,
			ProtectMethods: "POST,PUT,DELETE,PATCH",
			AllowedOrigins: "https://trusted.com\n*.partner.com",
			AllowEmptyRef:  allowEmptyRef,
			ExcludePaths:   excludePaths,
		}
		b, _ := json.Marshal(cfg)
		return &wafenginmodel.HostSafe{
			Host: model.Hosts{
				CsrfJSON:     string(b),
				BindMoreHost: "alias.com",
			},
		}
	}

	globalHostTarget := &wafenginmodel.HostSafe{}

	testCases := []struct {
		name          string
		method        string
		path          string
		host          string
		origin        string
		referer       string
		allowEmptyRef int
		excludePaths  string
		disabled      bool // 关闭 CSRF 防护
		expectBlocked bool
	}{
		{
			name:   "关闭防护-跨站Origin也放行",
			method: "POST", path: "/transfer", host: "self.com",
			origin: "https://evil.com", allowEmptyRef: 1, disabled: true,
			expectBlocked: false,
		},
		{
			name:   "GET安全方法-跨站Origin放行",
			method: "GET", path: "/page", host: "self.com",
			origin: "https://evil.com", allowEmptyRef: 1,
			expectBlocked: false,
		},
		{
			name:   "HEAD安全方法-跨站Origin放行",
			method: "HEAD", path: "/page", host: "self.com",
			origin: "https://evil.com", allowEmptyRef: 1,
			expectBlocked: false,
		},
		{
			name:   "POST同源Origin放行",
			method: "POST", path: "/transfer", host: "self.com",
			origin: "https://self.com", allowEmptyRef: 1,
			expectBlocked: false,
		},
		{
			name:   "POST同源Origin带端口放行",
			method: "POST", path: "/transfer", host: "self.com:8443",
			origin: "https://self.com:8443", allowEmptyRef: 1,
			expectBlocked: false,
		},
		{
			name:   "POST跨站Origin拦截",
			method: "POST", path: "/transfer", host: "self.com",
			origin: "https://evil.com", allowEmptyRef: 1,
			expectBlocked: true,
		},
		{
			name:   "POST无Origin同源Referer放行",
			method: "POST", path: "/transfer", host: "self.com",
			referer: "https://self.com/form", allowEmptyRef: 1,
			expectBlocked: false,
		},
		{
			name:   "POST无Origin跨站Referer拦截",
			method: "POST", path: "/transfer", host: "self.com",
			referer: "https://evil.com/form", allowEmptyRef: 1,
			expectBlocked: true,
		},
		{
			name:   "POST无来源头-allowEmptyRef=1放行",
			method: "POST", path: "/transfer", host: "self.com",
			allowEmptyRef: 1,
			expectBlocked: false,
		},
		{
			name:   "POST无来源头-allowEmptyRef=0拦截",
			method: "POST", path: "/transfer", host: "self.com",
			allowEmptyRef: 0,
			expectBlocked: true,
		},
		{
			name:   "Origin为null退化到同源Referer放行",
			method: "POST", path: "/transfer", host: "self.com",
			origin: "null", referer: "https://self.com/form", allowEmptyRef: 0,
			expectBlocked: false,
		},
		{
			name:   "Origin为null退化到跨站Referer拦截",
			method: "POST", path: "/transfer", host: "self.com",
			origin: "null", referer: "https://evil.com/form", allowEmptyRef: 1,
			expectBlocked: true,
		},
		{
			name:   "命中排除路径放行",
			method: "POST", path: "/api/webhook/notify", host: "self.com",
			origin: "https://evil.com", allowEmptyRef: 1, excludePaths: "/api/webhook",
			expectBlocked: false,
		},
		{
			name:   "额外允许来源trusted.com放行",
			method: "POST", path: "/transfer", host: "self.com",
			origin: "https://trusted.com", allowEmptyRef: 1,
			expectBlocked: false,
		},
		{
			name:   "BindMoreHost别名alias.com放行",
			method: "POST", path: "/transfer", host: "self.com",
			origin: "https://alias.com", allowEmptyRef: 1,
			expectBlocked: false,
		},
		{
			name:   "通配域名a.partner.com放行",
			method: "POST", path: "/transfer", host: "self.com",
			origin: "https://a.partner.com", allowEmptyRef: 1,
			expectBlocked: false,
		},
		{
			name:   "PUT跨站Origin拦截",
			method: "PUT", path: "/resource/1", host: "self.com",
			origin: "https://evil.com", allowEmptyRef: 1,
			expectBlocked: true,
		},
		{
			name:   "DELETE跨站Origin拦截",
			method: "DELETE", path: "/resource/1", host: "self.com",
			origin: "https://evil.com", allowEmptyRef: 1,
			expectBlocked: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hostTarget := buildHost(tc.allowEmptyRef, tc.excludePaths)
			if tc.disabled {
				hostTarget.Host.CsrfJSON = `{"is_enable":0}`
			}
			req, _ := http.NewRequest(tc.method, "http://"+tc.host+tc.path, nil)
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			weblog := &innerbean.WebLog{URL: tc.path}
			result := waf.CheckCsrf(req, weblog, url.Values{}, hostTarget, globalHostTarget)
			if result.IsBlock != tc.expectBlocked {
				t.Errorf("测试 '%s' 失败: 期望拦截=%v, 实际=%v", tc.name, tc.expectBlocked, result.IsBlock)
			}
		})
	}
}

func TestIsCsrfProtectedMethod(t *testing.T) {
	const methods = "POST,PUT,DELETE,PATCH"
	cases := []struct {
		method string
		want   bool
	}{
		{"POST", true},
		{"post", true},
		{" Put ", true},
		{"DELETE", true},
		{"PATCH", true},
		{"GET", false},
		{"HEAD", false},
		{"OPTIONS", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isCsrfProtectedMethod(c.method, methods); got != c.want {
			t.Errorf("isCsrfProtectedMethod(%q) = %v, 期望 %v", c.method, got, c.want)
		}
	}
}

func TestIsCsrfExcludedPath(t *testing.T) {
	const excludes = "/api/webhook\n/callback/\n"
	cases := []struct {
		path string
		want bool
	}{
		{"/api/webhook/notify", true},
		{"/api/webhook", true},
		{"/callback/wx", true},
		{"/transfer", false},
		{"/api/other", false},
	}
	for _, c := range cases {
		if got := isCsrfExcludedPath(c.path, excludes); got != c.want {
			t.Errorf("isCsrfExcludedPath(%q) = %v, 期望 %v", c.path, got, c.want)
		}
	}
	if isCsrfExcludedPath("/anything", "") {
		t.Errorf("空排除列表不应命中任何路径")
	}
}

func TestExtractHostFromOrigin(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com", "example.com"},
		{"https://example.com:8443", "example.com"},
		{"http://Example.COM/path?x=1", "example.com"},
		{"https://sub.example.com/a/b", "sub.example.com"},
		{"example.com", "example.com"},
		{"example.com:80", "example.com"},
		{"", ""},
	}
	for _, c := range cases {
		if got := extractHostFromOrigin(c.in); got != c.want {
			t.Errorf("extractHostFromOrigin(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

func TestIsCsrfOriginAllowed(t *testing.T) {
	allowed := []string{"self.com", "alias.com", "*.partner.com"}
	cases := []struct {
		host string
		want bool
	}{
		{"self.com", true},
		{"alias.com", true},
		{"a.partner.com", true},
		{"partner.com", true},
		{"evil.com", false},
		{"notself.com", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isCsrfOriginAllowed(c.host, allowed); got != c.want {
			t.Errorf("isCsrfOriginAllowed(%q) = %v, 期望 %v", c.host, got, c.want)
		}
	}
}

func TestBuildCsrfAllowedHosts(t *testing.T) {
	hosts := buildCsrfAllowedHosts("Self.com:8443", "alias1.com\nalias2.com", "https://trusted.com\n*.partner.com\n")
	expectContains := []string{"self.com", "alias1.com", "alias2.com", "trusted.com", "*.partner.com"}
	for _, e := range expectContains {
		if !contains(hosts, e) {
			t.Errorf("buildCsrfAllowedHosts 结果缺少 %q，实际=%v", e, hosts)
		}
	}
}
