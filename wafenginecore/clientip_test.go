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

// TestHeaderModeNoTrustList header 模式未填可信网段：保持原行为，无条件取指定头
func TestHeaderModeNoTrustList(t *testing.T) {
	waf := &WafEngine{}
	r := newReq("8.8.8.8:1234", map[string]string{"X-Real-IP": "1.2.3.4"})
	_, ip, _ := waf.getBizClientIP(r, model.Hosts{IPSourceMode: "header", IPRealHeader: "X-Real-IP"})
	if ip != "1.2.3.4" {
		t.Errorf("未填可信网段时应直接取头 1.2.3.4，实际 %s", ip)
	}
}

// TestHeaderModeTrustList header 模式填了可信网段：来源不符时忽略伪造头，回退网络层
func TestHeaderModeTrustList(t *testing.T) {
	waf := &WafEngine{}
	host := model.Hosts{IPSourceMode: "header", IPRealHeader: "X-Real-IP", IPTrustProxies: "172.16.0.0/12"}

	// 攻击者直连并伪造 X-Real-IP → 来源不在可信网段，必须回退网络层
	r := newReq("8.8.8.8:1234", map[string]string{"X-Real-IP": "1.2.3.4"})
	_, ip, _ := waf.getBizClientIP(r, host)
	if ip != "8.8.8.8" {
		t.Errorf("来源不可信时伪造头应被拒，回退网络层 8.8.8.8，实际 %s", ip)
	}

	// 来自可信代理 → 信任该头
	r2 := newReq("172.16.0.5:1234", map[string]string{"X-Real-IP": "1.2.3.4"})
	_, ip2, _ := waf.getBizClientIP(r2, host)
	if ip2 != "1.2.3.4" {
		t.Errorf("可信来源应取头 1.2.3.4，实际 %s", ip2)
	}
}

// TestCDNPresetManualTrustProxies 厂商回源段拉不到时(如 EdgeOne 免费版)，手填可信网段应能兜底生效
func TestCDNPresetManualTrustProxies(t *testing.T) {
	waf := &WafEngine{}
	// 故意不给 edgeone 配置任何回源段，模拟免费版无法自动拉取
	host := model.Hosts{IPSourceMode: "cdn_preset", CDNProvider: "edgeone", IPTrustProxies: "43.152.0.0/16"}

	// 手填网段内的回源 → 信任 EdgeOne 默认头 EO-Connecting-IP
	r := newReq("43.152.1.2:1234", map[string]string{"EO-Connecting-IP": "1.2.3.4"})
	_, ip, _ := waf.getBizClientIP(r, host)
	if ip != "1.2.3.4" {
		t.Errorf("手填回源段应生效并取 EO-Connecting-IP=1.2.3.4，实际 %s", ip)
	}

	// 网段外直连伪造 → 回退网络层
	r2 := newReq("8.8.8.8:1234", map[string]string{"EO-Connecting-IP": "1.2.3.4"})
	_, ip2, _ := waf.getBizClientIP(r2, host)
	if ip2 != "8.8.8.8" {
		t.Errorf("非回源段伪造应被拒，回退网络层 8.8.8.8，实际 %s", ip2)
	}
}

// TestEdgeOneDefaultHeader EdgeOne 默认头必须是回源默认携带的 EO-Connecting-IP，
// 而不是默认关闭、且头名用户可自定义的 EO-Client-IP
func TestEdgeOneDefaultHeader(t *testing.T) {
	if got := clientip.DefaultHeader("edgeone"); got != "EO-Connecting-IP" {
		t.Errorf("EdgeOne 默认头应为 EO-Connecting-IP，实际 %s", got)
	}
}

// TestCDNPresetCustomHeaderOverride cdn_preset 下填了头名应覆盖厂商默认头
// (对应用户在 EdgeOne 控制台开启自定义「客户端IP头部」的场景)
func TestCDNPresetCustomHeaderOverride(t *testing.T) {
	waf := &WafEngine{}
	host := model.Hosts{IPSourceMode: "cdn_preset", CDNProvider: "edgeone",
		IPRealHeader: "My-Client-IP", IPTrustProxies: "43.152.0.0/16"}
	r := newReq("43.152.1.2:1234", map[string]string{
		"EO-Connecting-IP": "9.9.9.9",
		"My-Client-IP":     "1.2.3.4",
	})
	_, ip, _ := waf.getBizClientIP(r, host)
	if ip != "1.2.3.4" {
		t.Errorf("自定义头应覆盖厂商默认头，期望 1.2.3.4，实际 %s", ip)
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
