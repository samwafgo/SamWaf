package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafenginecore/clientip"
	"SamWaf/wafenginecore/ipset"
	"net/http"
	"testing"
)

func newReq(remoteAddr string, headers map[string]string) *http.Request {
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// TestCompatModeTakesLeftmost 验证 IPSourceMode="" 保持旧行为：取 X-Forwarded-For 最左第一个(向后兼容硬约束)
func TestCompatModeTakesLeftmost(t *testing.T) {
	old := global.GCONFIG_RECORD_PROXY_HEADER
	global.GCONFIG_RECORD_PROXY_HEADER = "X-Forwarded-For"
	defer func() { global.GCONFIG_RECORD_PROXY_HEADER = old }()

	waf := &WafEngine{}
	r := newReq("10.0.0.1:1234", map[string]string{"X-Forwarded-For": "1.1.1.1, 2.2.2.2, 3.3.3.3"})
	host := model.Hosts{IPSourceMode: ""}
	err, ip, _ := waf.getBizClientIP(r, host)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "1.1.1.1" {
		t.Errorf("兼容模式应取最左 1.1.1.1，实际 %s", ip)
	}
}

// TestNicMode 网卡模式取网络层直连 IP
func TestNicMode(t *testing.T) {
	waf := &WafEngine{}
	r := newReq("10.0.0.9:5555", map[string]string{"X-Forwarded-For": "1.1.1.1"})
	_, ip, _ := waf.getBizClientIP(r, model.Hosts{IPSourceMode: "nic"})
	if ip != "10.0.0.9" {
		t.Errorf("nic 模式应取网络层 10.0.0.9，实际 %s", ip)
	}
}

// TestXFFDepthTrusted 配了可信网段：从右往左跳过可信 hop，取最右非可信
func TestXFFDepthTrusted(t *testing.T) {
	waf := &WafEngine{}
	// XFF: 客户端伪造 evil, 真实客户端 9.9.9.9, 两层可信代理 172.16/12
	r := newReq("172.16.0.1:80", map[string]string{
		"X-Forwarded-For": "6.6.6.6, 9.9.9.9, 172.16.0.5, 172.16.0.1",
	})
	host := model.Hosts{IPSourceMode: "xff_depth", IPTrustProxies: "172.16.0.0/12"}
	_, ip, _ := waf.getBizClientIP(r, host)
	if ip != "9.9.9.9" {
		t.Errorf("应取最右非可信 9.9.9.9，实际 %s", ip)
	}
}

// TestXFFDepthByDepth 无可信网段：按 depth 从右取第 N 个
func TestXFFDepthByDepth(t *testing.T) {
	waf := &WafEngine{}
	r := newReq("172.16.0.1:80", map[string]string{"X-Forwarded-For": "1.1.1.1, 2.2.2.2, 3.3.3.3"})
	// depth=2 → 从右起第2个 = 2.2.2.2
	_, ip, _ := waf.getBizClientIP(r, model.Hosts{IPSourceMode: "xff_depth", IPTrustDepth: 2})
	if ip != "2.2.2.2" {
		t.Errorf("depth=2 应取 2.2.2.2，实际 %s", ip)
	}
}

// TestCDNPresetSpoofRejected cdn_preset：直连非厂商段时忽略伪造头，回退网络层
func TestCDNPresetSpoofRejected(t *testing.T) {
	// 配置 cloudflare 回源段仅含 103.21.244.0/22
	clientip.SetProviderRanges("cloudflare", ipset.BuildMatchSet([]string{"103.21.244.0/22"}))
	waf := &WafEngine{}
	host := model.Hosts{IPSourceMode: "cdn_preset", CDNProvider: "cloudflare"}

	// 直连对端不是 CF 段(攻击者直连并伪造 CF-Connecting-IP) → 应回退网络层，伪造无效
	r := newReq("8.8.8.8:1234", map[string]string{"CF-Connecting-IP": "1.2.3.4"})
	_, ip, _ := waf.getBizClientIP(r, host)
	if ip != "8.8.8.8" {
		t.Errorf("非 CF 来源伪造应被拒，回退网络层 8.8.8.8，实际 %s", ip)
	}

	// 直连对端是 CF 段 → 信任 CF-Connecting-IP
	r2 := newReq("103.21.244.10:1234", map[string]string{"CF-Connecting-IP": "1.2.3.4"})
	_, ip2, _ := waf.getBizClientIP(r2, host)
	if ip2 != "1.2.3.4" {
		t.Errorf("CF 来源应信任真实 IP 头 1.2.3.4，实际 %s", ip2)
	}
}
