package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/model"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// newProbeRequest 造一个带常见头的请求
func newProbeRequest(remoteAddr string) *http.Request {
	r := httptest.NewRequest("GET", "/probe/path?a=1", nil)
	r.RemoteAddr = remoteAddr
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.9")
	r.Header.Set("Ali-Cdn-Real-Ip", "1.2.3.4")
	r.Header.Set("Cookie", "SESSIONID=verysecret")
	r.Header.Set("Authorization", "Bearer abc.def.ghi")
	r.Header.Set("X-Custom-Token", "should-not-leak")
	r.Header.Set("User-Agent", "probe-ua")
	return r
}

// enableProbe 打开探针开关(默认关)，测试结束自动还原
func enableProbe(t *testing.T) {
	t.Helper()
	old := global.GCONFIG_IPPROBE_ENABLE
	global.GCONFIG_IPPROBE_ENABLE = 1
	t.Cleanup(func() { global.GCONFIG_IPPROBE_ENABLE = old })
}

// forceProbeSample 允许下一次立刻采样(绕开每秒限频，避免测试里 sleep)
func forceProbeSample(hostCode string) {
	if v, ok := ipProbeStore.Load(hostCode); ok {
		atomic.StoreInt64(&v.(*ipProbeEntry).lastAt, 0)
	}
}

// TestRecordIPProbeMasksSensitiveHeaders 采样必须记录到真实头，但 Cookie/鉴权类一律脱敏(CLAUDE.md 日志脱敏要求)
func TestRecordIPProbeMasksSensitiveHeaders(t *testing.T) {
	enableProbe(t)
	host := model.Hosts{Code: "probe-mask", IPSourceMode: "cdn_preset", CDNProvider: "aliyun"}
	recordIPProbe(host, newProbeRequest("47.246.1.1:12345"), "47.246.1.1")

	samples := GetIPProbeSamples(host.Code)
	if len(samples) != 1 {
		t.Fatalf("期望采到1条样本，实际 %d", len(samples))
	}
	s := samples[0]
	if s.NetIP != "47.246.1.1" || s.ResolvedIP != "47.246.1.1" || !s.Fallback {
		t.Fatalf("网络层/解析IP记录错误: %+v", s)
	}
	found := map[string]IPProbeHeader{}
	for _, h := range s.Headers {
		found[h.Name] = h
	}
	if xff := found["X-Forwarded-For"]; !xff.IsIPHeader || xff.ParsedIP != "1.2.3.4" || xff.Value == "" {
		t.Fatalf("XFF 头解析错误: %+v", xff)
	}
	if ali := found["Ali-Cdn-Real-Ip"]; !ali.IsIPHeader || ali.ParsedIP != "1.2.3.4" {
		t.Fatalf("Ali-Cdn-Real-Ip 头解析错误: %+v", ali)
	}
	for _, name := range []string{"Cookie", "Authorization", "X-Custom-Token"} {
		h, ok := found[name]
		if !ok {
			t.Fatalf("缺少头 %s", name)
		}
		if !h.Masked || h.Value != "***" {
			t.Fatalf("敏感头 %s 未脱敏: %+v", name, h)
		}
	}
}

// TestRecordIPProbeThrottleAndRing 同站每秒最多一条，且只保留最近 ipProbeMaxSamples 条
func TestRecordIPProbeThrottleAndRing(t *testing.T) {
	enableProbe(t)
	host := model.Hosts{Code: "probe-ring"}
	recordIPProbe(host, newProbeRequest("8.8.8.8:1000"), "8.8.8.8")
	recordIPProbe(host, newProbeRequest("8.8.8.9:1000"), "8.8.8.9") //一秒内的第二次应被限频丢弃
	if got := len(GetIPProbeSamples(host.Code)); got != 1 {
		t.Fatalf("限频失效，期望1条实际 %d", got)
	}
	for i := 0; i < ipProbeMaxSamples+3; i++ {
		forceProbeSample(host.Code)
		recordIPProbe(host, newProbeRequest("8.8.8.8:1000"), "8.8.8.8")
	}
	if got := len(GetIPProbeSamples(host.Code)); got != ipProbeMaxSamples {
		t.Fatalf("环形缓冲未封顶，期望 %d 实际 %d", ipProbeMaxSamples, got)
	}

	ClearIPProbeSamples(host.Code)
	if got := len(GetIPProbeSamples(host.Code)); got != 0 {
		t.Fatalf("清空失败，剩余 %d", got)
	}
}

// TestRecordIPProbeDisabledByDefault 开关默认关闭时一条都不能采(用户关心的流量/开销问题)
func TestRecordIPProbeDisabledByDefault(t *testing.T) {
	old := global.GCONFIG_IPPROBE_ENABLE
	global.GCONFIG_IPPROBE_ENABLE = 0
	defer func() { global.GCONFIG_IPPROBE_ENABLE = old }()

	host := model.Hosts{Code: "probe-off"}
	recordIPProbe(host, newProbeRequest("8.8.8.8:1000"), "8.8.8.8")
	if got := len(GetIPProbeSamples(host.Code)); got != 0 {
		t.Fatalf("探针关闭时不应采样，实际 %d 条", got)
	}
	if IPProbeEnabled() {
		t.Fatal("IPProbeEnabled 应为 false")
	}

	// 开→采到→关，ClearAllIPProbeSamples 必须把内存清干净
	global.GCONFIG_IPPROBE_ENABLE = 1
	recordIPProbe(host, newProbeRequest("8.8.8.8:1000"), "8.8.8.8")
	if got := len(GetIPProbeSamples(host.Code)); got != 1 {
		t.Fatalf("开启后应采到1条，实际 %d 条", got)
	}
	ClearAllIPProbeSamples()
	if got := len(GetIPProbeSamples(host.Code)); got != 0 {
		t.Fatalf("关闭探针后样本应被清空，实际 %d 条", got)
	}
}

// TestIPSourceEffectiveHeader 各模式生效头名要和 getBizClientIP 的取值口径一致
func TestIPSourceEffectiveHeader(t *testing.T) {
	cases := []struct {
		host model.Hosts
		want string
	}{
		{model.Hosts{IPSourceMode: "header", IPRealHeader: "X-Real-IP"}, "X-Real-IP"},
		{model.Hosts{IPSourceMode: "xff_depth"}, "X-Forwarded-For"},
		{model.Hosts{IPSourceMode: "xff_depth", IPRealHeader: "X-Original-Forwarded-For"}, "X-Original-Forwarded-For"},
		{model.Hosts{IPSourceMode: "cdn_preset", CDNProvider: "cloudflare"}, "CF-Connecting-IP"},
		{model.Hosts{IPSourceMode: "cdn_preset", CDNProvider: "cloudflare", IPRealHeader: "X-My-IP"}, "X-My-IP"},
		{model.Hosts{IPSourceMode: "nic"}, ""},
	}
	for _, c := range cases {
		if got := IPSourceEffectiveHeader(c.host); got != c.want {
			t.Fatalf("模式 %s 期望头 %q 实际 %q", c.host.IPSourceMode, c.want, got)
		}
	}
}

// TestIsIPSourceTrustedPeer cdn_preset 没有任何可信来源时必须判为不可信(这正是 #956 的现象：一直取到回源节点IP)
func TestIsIPSourceTrustedPeer(t *testing.T) {
	noTrust := model.Hosts{IPSourceMode: "cdn_preset", CDNProvider: "aliyun"}
	if IsIPSourceTrustedPeer(noTrust, "47.246.1.1") {
		t.Fatal("厂商回源段未下载且未填可信网段时不应判为可信")
	}
	withTrust := model.Hosts{IPSourceMode: "cdn_preset", CDNProvider: "aliyun", IPTrustProxies: "47.246.0.0/16"}
	if !IsIPSourceTrustedPeer(withTrust, "47.246.1.1") {
		t.Fatal("手填可信网段命中时应判为可信")
	}
	if IsIPSourceTrustedPeer(withTrust, "1.2.3.4") {
		t.Fatal("不在可信网段内不应判为可信")
	}
	// header 模式留空可信网段 = 不校验来源，保持既有行为
	if !IsIPSourceTrustedPeer(model.Hosts{IPSourceMode: "header"}, "1.2.3.4") {
		t.Fatal("header 模式未填可信网段时应视为不校验")
	}
}
