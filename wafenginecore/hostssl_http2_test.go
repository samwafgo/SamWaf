package wafenginecore

import (
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"crypto/tls"
	"net"
	"testing"
)

// regHost 在测试路由表里注册一个站点（主域名精确 key），返回其 HostSafe。
// disableHTTP2: 该站点的 DisableHTTP2 取值。
func regHost(waf *WafEngine, code, host string, port string, disableHTTP2 int) *wafenginmodel.HostSafe {
	hs := &wafenginmodel.HostSafe{Host: model.Hosts{
		Code:         code,
		Host:         host,
		DisableHTTP2: disableHTTP2,
	}}
	waf.rt().HostTarget[host+":"+port] = hs
	waf.rt().HostCode[code] = host + ":" + port
	return hs
}

// TestIsHTTP2Disabled_ExactHost 精确域名：默认(0)不关、置1则关
func TestIsHTTP2Disabled_ExactHost(t *testing.T) {
	waf := newTestWafEngine()
	regHost(waf, "c_on", "on.example.com", "443", 0)
	regHost(waf, "c_off", "off.example.com", "443", 1)

	if waf.isHTTP2DisabledForServerName("on.example.com", "443") {
		t.Errorf("默认站点 DisableHTTP2=0 不应关 h2")
	}
	if !waf.isHTTP2DisabledForServerName("off.example.com", "443") {
		t.Errorf("DisableHTTP2=1 的站点应关 h2")
	}
}

// TestIsHTTP2Disabled_UnknownSNI 未注册 SNI 一律 fail-open（保持 h2）
func TestIsHTTP2Disabled_UnknownSNI(t *testing.T) {
	waf := newTestWafEngine()
	regHost(waf, "c_off", "off.example.com", "443", 1)

	if waf.isHTTP2DisabledForServerName("stranger.example.com", "443") {
		t.Errorf("未注册 SNI 应 fail-open 不关 h2")
	}
	if waf.isHTTP2DisabledForServerName("", "443") {
		t.Errorf("空 SNI 应 fail-open 不关 h2")
	}
}

// TestIsHTTP2Disabled_Wildcard 泛域名匹配 *.example.com
func TestIsHTTP2Disabled_Wildcard(t *testing.T) {
	waf := newTestWafEngine()
	// 站点以泛域名形式注册（MaskSubdomain 生成 *.example.com:443）
	regHost(waf, "c_wild", "*.example.com", "443", 1)

	if !waf.isHTTP2DisabledForServerName("a.example.com", "443") {
		t.Errorf("一级子域名应命中泛域名站点并关 h2")
	}
	// MaskSubdomain 只替换首段：deep.a.example.com -> *.a.example.com，不命中 *.example.com → fail-open
	if waf.isHTTP2DisabledForServerName("deep.a.example.com", "443") {
		t.Errorf("多级子域不应命中 *.example.com，应 fail-open 不关 h2")
	}
}

// TestIsHTTP2Disabled_MoreDomain 绑定多域名：副域名也应生效
func TestIsHTTP2Disabled_MoreDomain(t *testing.T) {
	waf := newTestWafEngine()
	hs := regHost(waf, "c_multi", "main.example.com", "443", 1)
	_ = hs
	// 副域名 alias.example.com:443 -> code
	waf.rt().HostTargetMoreDomain["alias.example.com:443"] = "c_multi"

	if !waf.isHTTP2DisabledForServerName("main.example.com", "443") {
		t.Errorf("主域名应关 h2")
	}
	if !waf.isHTTP2DisabledForServerName("alias.example.com", "443") {
		t.Errorf("绑定的副域名应同样关 h2")
	}
}

// TestIsHTTP2Disabled_LoosePort 宽松端口：按纯域名映射，端口不敏感
func TestIsHTTP2Disabled_LoosePort(t *testing.T) {
	waf := newTestWafEngine()
	hs := &wafenginmodel.HostSafe{Host: model.Hosts{Code: "c_loose", Host: "loose.example.com", DisableHTTP2: 1}}
	waf.rt().HostTarget["loose.example.com:443"] = hs
	waf.rt().HostCode["c_loose"] = "loose.example.com:443"
	// 宽松端口映射：纯域名 -> 具体 host:port
	waf.rt().HostTargetNoPort["loose.example.com"] = "loose.example.com:443"

	// 即便来源端口是 8443，也应经 NoPort 命中并关 h2
	if !waf.isHTTP2DisabledForServerName("loose.example.com", "8443") {
		t.Errorf("宽松端口站点应不分端口命中并关 h2")
	}
}

// TestIsHTTP2Disabled_WildPort 通配端口 *:port
func TestIsHTTP2Disabled_WildPort(t *testing.T) {
	waf := newTestWafEngine()
	hs := &wafenginmodel.HostSafe{Host: model.Hosts{Code: "c_star", Host: "*", DisableHTTP2: 1}}
	waf.rt().HostTarget["*:8443"] = hs
	waf.rt().HostCode["c_star"] = "*:8443"

	if !waf.isHTTP2DisabledForServerName("anything.example.com", "8443") {
		t.Errorf("通配端口 *:8443 应命中并关 h2")
	}
	if waf.isHTTP2DisabledForServerName("anything.example.com", "443") {
		t.Errorf("端口不匹配(443)不应命中 *:8443")
	}
}

// mockLocalAddrConn 提供固定 LocalAddr 的假连接，用于 GetTLSConfigForClient 取端口
type mockLocalAddrConn struct {
	net.Conn
	local net.Addr
}

func (m *mockLocalAddrConn) LocalAddr() net.Addr { return m.local }

type mockAddr struct{ s string }

func (a mockAddr) Network() string { return "tcp" }
func (a mockAddr) String() string  { return a.s }

// TestGetTLSConfigForClient_ALPN 端到端验证：关 h2 站点 ALPN 只给 http/1.1，其余给 h2+http/1.1
func TestGetTLSConfigForClient_ALPN(t *testing.T) {
	waf := newTestWafEngine()
	regHost(waf, "c_on", "on.example.com", "443", 0)
	regHost(waf, "c_off", "off.example.com", "443", 1)

	conn := &mockLocalAddrConn{local: mockAddr{s: "10.0.0.1:443"}}

	// 关 h2 的站点：只 http/1.1
	cfgOff, err := waf.GetTLSConfigForClient(&tls.ClientHelloInfo{ServerName: "off.example.com", Conn: conn})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got := cfgOff.NextProtos; len(got) != 1 || got[0] != "http/1.1" {
		t.Errorf("关 h2 站点 NextProtos 应为 [http/1.1]，实际 %v", got)
	}

	// 默认站点：h2 + http/1.1
	cfgOn, err := waf.GetTLSConfigForClient(&tls.ClientHelloInfo{ServerName: "on.example.com", Conn: conn})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got := cfgOn.NextProtos; len(got) != 2 || got[0] != "h2" || got[1] != "http/1.1" {
		t.Errorf("默认站点 NextProtos 应为 [h2 http/1.1]，实际 %v", got)
	}

	// 未注册 SNI：fail-open 给 h2
	cfgUnknown, _ := waf.GetTLSConfigForClient(&tls.ClientHelloInfo{ServerName: "stranger.example.com", Conn: conn})
	if got := cfgUnknown.NextProtos; len(got) != 2 || got[0] != "h2" {
		t.Errorf("未注册 SNI 应 fail-open 给 h2，实际 %v", got)
	}

	// GetCertificate 仍被携带（cert 选择不受影响）
	if cfgOff.GetCertificate == nil || cfgOn.GetCertificate == nil {
		t.Errorf("返回的 TLS config 应仍提供 GetCertificate")
	}
}
