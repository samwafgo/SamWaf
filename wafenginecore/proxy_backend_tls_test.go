package wafenginecore

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"net/http"
	"testing"
)

// TestCreateTransport_BackendSchemeGatesTLS 验证：后端是否挂 TLS 配置由“后端协议”(backendScheme)决定，
// 而非客户端连接协议 r.TLS。修复 “HTTP 进 → HTTPS 后端” 时 InsecureSkipVerify 被静默忽略的问题。
func TestCreateTransport_BackendSchemeGatesTLS(t *testing.T) {
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "json")
	waf := &WafEngine{}
	// 客户端以明文 HTTP 进入（r.TLS == nil），后端为 HTTPS
	r, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1/", nil)

	cases := []struct {
		name          string
		backendScheme string
		skipVerify    int
		wantTLS       bool
		wantInsecure  bool
	}{
		{"https后端+跳过校验", "https", 1, true, true},
		{"https后端+校验", "https", 0, true, false},
		{"http后端不挂TLS", "http", 1, false, false},
		{"空scheme不挂TLS", "", 1, false, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hostTarget := &wafenginmodel.HostSafe{Host: model.Hosts{
				InsecureSkipVerify: c.skipVerify,
			}}
			transport, _ := waf.createTransport(r, "127.0.0.1", 0, model.LoadBalance{}, hostTarget, c.backendScheme)

			if c.wantTLS {
				if transport.TLSClientConfig == nil {
					t.Fatalf("backendScheme=%q 期望挂载 TLSClientConfig，实际为 nil", c.backendScheme)
				}
				if got := transport.TLSClientConfig.InsecureSkipVerify; got != c.wantInsecure {
					t.Errorf("InsecureSkipVerify 期望 %v，实际 %v", c.wantInsecure, got)
				}
			} else if transport.TLSClientConfig != nil {
				t.Errorf("backendScheme=%q 期望不挂 TLSClientConfig，实际非 nil", c.backendScheme)
			}
		})
	}
}

// TestGenerateTransportKey_IncludesBackendScheme 验证缓存 key 含 backendScheme，
// 避免 http/https 不同后端协议命中同一条缓存 transport。
func TestGenerateTransportKey_IncludesBackendScheme(t *testing.T) {
	waf := &WafEngine{}
	hostTarget := &wafenginmodel.HostSafe{Host: model.Hosts{
		Remote_ip:          "192.168.3.10",
		Remote_port:        8007,
		InsecureSkipVerify: 1,
	}}
	keyHTTPS := waf.generateTransportKey("h", 0, model.LoadBalance{}, hostTarget, "https")
	keyHTTP := waf.generateTransportKey("h", 0, model.LoadBalance{}, hostTarget, "http")
	if keyHTTPS == keyHTTP {
		t.Errorf("不同后端协议应产生不同缓存 key，https=%q http=%q", keyHTTPS, keyHTTP)
	}
}
