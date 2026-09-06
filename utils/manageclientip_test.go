package utils

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"SamWaf/global"
	"SamWaf/wafenginecore/clientip"
	"SamWaf/wafenginecore/ipset"

	"github.com/gin-gonic/gin"
)

func newManageCtx(remoteAddr string, headers map[string]string) *gin.Context {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c.Request = req
	return c
}

// withManageIPConfig 临时设置管理端真实IP相关的三个全局配置，跑完还原
func withManageIPConfig(t *testing.T, proxyHeader, trustedProxies, cdnProvider string, fn func()) {
	t.Helper()
	oldHeader, oldTrusted, oldCDN := global.GCONFIG_MANAGE_PROXY_HEADER, global.GCONFIG_MANAGE_TRUSTED_PROXIES, global.GCONFIG_MANAGE_CDN_PROVIDER
	defer func() {
		global.GCONFIG_MANAGE_PROXY_HEADER, global.GCONFIG_MANAGE_TRUSTED_PROXIES, global.GCONFIG_MANAGE_CDN_PROVIDER = oldHeader, oldTrusted, oldCDN
	}()
	global.GCONFIG_MANAGE_PROXY_HEADER, global.GCONFIG_MANAGE_TRUSTED_PROXIES, global.GCONFIG_MANAGE_CDN_PROVIDER = proxyHeader, trustedProxies, cdnProvider
	fn()
}

// TestGetManageClientIP 管理端真实IP取值矩阵。
// 前三组来自 issue #994：可信代理网段覆盖到真实客户端 IP 时，该 IP 不能被当作代理 hop 剔掉。
func TestGetManageClientIP(t *testing.T) {
	cases := []struct {
		name        string
		proxyHeader string
		trusted     string
		cdnProvider string
		remoteAddr  string
		headers     map[string]string
		want        string
		wantReason  string
	}{
		{
			// 0.0.0.0/0 等于没有闸门：头里的值与伪造不可区分，维持回退网络层IP（不因本次修正而变成可伪造）
			name:        "过宽网段(0.0.0.0/0)：代理头不予采信，仍取网络层IP",
			proxyHeader: "CF-Connecting-IP",
			trusted:     "0.0.0.0/0",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"CF-Connecting-IP": "1.2.3.4"},
			want:        "172.17.0.1",
			wantReason:  ManageIPReasonOverBroadGate,
		},
		{
			name:        "过宽网段(把全网拆两半)：同样不予采信",
			proxyHeader: "CF-Connecting-IP",
			trusted:     "0.0.0.0/1,128.0.0.0/1",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"CF-Connecting-IP": "1.2.3.4"},
			want:        "172.17.0.1",
			wantReason:  ManageIPReasonOverBroadGate,
		},
		{
			name:        "精确网关可信+单值CF头",
			proxyHeader: "CF-Connecting-IP",
			trusted:     "172.17.0.1",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"CF-Connecting-IP": "1.2.3.4"},
			want:        "1.2.3.4",
			wantReason:  ManageIPReasonRightmostUntrusted,
		},
		{
			name:        "内网大段可信+客户端本身也在内网",
			proxyHeader: "CF-Connecting-IP",
			trusted:     "10.0.0.0/8,172.16.0.0/12",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"CF-Connecting-IP": "10.1.2.3"},
			want:        "10.1.2.3",
			wantReason:  ManageIPReasonAllTrustedLeftmost,
		},
		{
			name:        "多跳XFF整条链都可信：取最左(链的起点)",
			proxyHeader: "X-Forwarded-For",
			trusted:     "10.0.0.0/8,172.16.0.0/12",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"X-Forwarded-For": "10.1.2.3, 10.0.0.5"},
			want:        "10.1.2.3",
			wantReason:  ManageIPReasonAllTrustedLeftmost,
		},
		{
			name:        "多跳XFF右侧有非可信hop：取最右非可信(伪造值在左侧)",
			proxyHeader: "X-Forwarded-For",
			trusted:     "10.0.0.0/8,172.16.0.0/12",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"X-Forwarded-For": "6.6.6.6, 1.2.3.4, 10.0.0.5"},
			want:        "1.2.3.4",
			wantReason:  ManageIPReasonRightmostUntrusted,
		},
		{
			name:        "直连对端不可信：伪造代理头一律忽略，按网络层IP",
			proxyHeader: "X-Forwarded-For",
			trusted:     "10.0.0.0/8",
			remoteAddr:  "203.0.113.9:5555",
			headers:     map[string]string{"X-Forwarded-For": "1.2.3.4"},
			want:        "203.0.113.9",
			wantReason:  ManageIPReasonPeerUntrusted,
		},
		{
			name:        "可信代理网段留空：不信任任何代理头",
			proxyHeader: "X-Forwarded-For",
			trusted:     "",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"X-Forwarded-For": "1.2.3.4"},
			want:        "172.17.0.1",
			wantReason:  ManageIPReasonPeerUntrusted,
		},
		{
			name:       "未配代理头：直接用网络层IP",
			trusted:    "0.0.0.0/0",
			remoteAddr: "172.17.0.1:41234",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4"},
			want:       "172.17.0.1",
			wantReason: ManageIPReasonNoProxyHeader,
		},
		{
			name:        "头缺失：回退网络层IP",
			proxyHeader: "CF-Connecting-IP",
			trusted:     "172.17.0.1",
			remoteAddr:  "172.17.0.1:41234",
			want:        "172.17.0.1",
			wantReason:  ManageIPReasonNoValidHeader,
		},
		{
			name:        "头值全非法：回退网络层IP",
			proxyHeader: "X-Forwarded-For",
			trusted:     "172.17.0.1",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"X-Forwarded-For": "unknown, not-an-ip"},
			want:        "172.17.0.1",
			wantReason:  ManageIPReasonNoValidHeader,
		},
		{
			name:        "多头按优先级：第一个头无值时看第二个",
			proxyHeader: "X-Forwarded-For, CF-Connecting-IP",
			trusted:     "172.17.0.1",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"CF-Connecting-IP": "1.2.3.4"},
			want:        "1.2.3.4",
			wantReason:  ManageIPReasonRightmostUntrusted,
		},
		{
			name:        "非法值夹在中间不影响取值",
			proxyHeader: "X-Forwarded-For",
			trusted:     "10.0.0.0/8",
			remoteAddr:  "10.0.0.5:41234",
			headers:     map[string]string{"X-Forwarded-For": "1.2.3.4, unknown, 10.0.0.5"},
			want:        "1.2.3.4",
			wantReason:  ManageIPReasonRightmostUntrusted,
		},
		{
			name:        "IPv6单值头",
			proxyHeader: "CF-Connecting-IP",
			trusted:     "fd00::/8",
			remoteAddr:  "[fd00::1]:41234",
			headers:     map[string]string{"CF-Connecting-IP": "2001:db8::1"},
			want:        "2001:db8::1",
			wantReason:  ManageIPReasonRightmostUntrusted,
		},
		{
			name:        "private关键字：容器网关可信、真实IP照常取出",
			proxyHeader: "CF-Connecting-IP",
			trusted:     "private",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"CF-Connecting-IP": "1.2.3.4"},
			want:        "1.2.3.4",
			wantReason:  ManageIPReasonRightmostUntrusted,
		},
		{
			name:        "private关键字：公网对端不可信",
			proxyHeader: "CF-Connecting-IP",
			trusted:     "private",
			remoteAddr:  "203.0.113.9:5555",
			headers:     map[string]string{"CF-Connecting-IP": "1.2.3.4"},
			want:        "203.0.113.9",
			wantReason:  ManageIPReasonPeerUntrusted,
		},
		{
			name:        "private与具体网段混写",
			proxyHeader: "CF-Connecting-IP",
			trusted:     "private, 203.0.113.9",
			remoteAddr:  "203.0.113.9:5555",
			headers:     map[string]string{"CF-Connecting-IP": "1.2.3.4"},
			want:        "1.2.3.4",
			wantReason:  ManageIPReasonRightmostUntrusted,
		},
		{
			// 上游 nginx 只写了 X-Real-IP、把客户端自带的 XFF 原样转发：
			// XFF 里那个"落在可信网段内"的值不能抢在 X-Real-IP 前面被采信
			name:        "首个头是上游未净化的XFF：不能劫持后面说真话的头",
			proxyHeader: "X-Forwarded-For, X-Real-IP",
			trusted:     "10.0.0.0/8",
			remoteAddr:  "10.0.0.5:1234",
			headers:     map[string]string{"X-Forwarded-For": "10.0.0.99", "X-Real-IP": "203.0.113.7"},
			want:        "203.0.113.7",
			wantReason:  ManageIPReasonRightmostUntrusted,
		},
		{
			name:        "跳数超上限的畸形头：整头丢弃，回退网络层",
			proxyHeader: "X-Forwarded-For",
			trusted:     "172.17.0.1",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"X-Forwarded-For": strings.Repeat("1.2.3.4,", maxManageProxyHops+1) + "1.2.3.4"},
			want:        "172.17.0.1",
			wantReason:  ManageIPReasonNoValidHeader,
		},
		{
			// 0.0.0.0/0 是 4 字节掩码，IPNet.Contains 对 IPv6 恒为 false：
			// 异族的伪造值不能因此被当成"非可信 hop"直接采信
			name:        "过宽网段 + 异族(IPv6)伪造头：仍不予采信",
			proxyHeader: "X-Forwarded-For",
			trusted:     "0.0.0.0/0",
			remoteAddr:  "203.0.113.9:5555",
			headers:     map[string]string{"X-Forwarded-For": "2001:db8::dead"},
			want:        "203.0.113.9",
			wantReason:  ManageIPReasonOverBroadGate,
		},
		{
			name:        "过宽网段(::/0) + 异族(IPv4)伪造头：仍不予采信",
			proxyHeader: "X-Forwarded-For",
			trusted:     "::/0",
			remoteAddr:  "[2001:db8::1]:5555",
			headers:     map[string]string{"X-Forwarded-For": "8.8.8.8"},
			want:        "2001:db8::1",
			wantReason:  ManageIPReasonOverBroadGate,
		},
		{
			// 窄条目让闸门通过，但过宽条目不得给 hop 盖"可信"章，
			// 否则伪造的公网 IP 会被推给第二轮当成链起点采信
			name:        "窄+过宽混写：过宽条目不参与逐跳判定",
			proxyHeader: "X-Forwarded-For",
			trusted:     "10.0.0.0/8,0.0.0.0/0",
			remoteAddr:  "10.0.0.5:1234",
			headers:     map[string]string{"X-Forwarded-For": "8.8.8.8, 203.0.113.7"},
			want:        "203.0.113.7",
			wantReason:  ManageIPReasonRightmostUntrusted,
		},
		{
			name:        "IPv4-mapped 十六进制写法同样归一",
			proxyHeader: "CF-Connecting-IP",
			trusted:     "172.17.0.1",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"CF-Connecting-IP": "::ffff:102:304"},
			want:        "1.2.3.4",
			wantReason:  ManageIPReasonRightmostUntrusted,
		},
		{
			name:        "IPv6 大写/非压缩写法归一成小写压缩",
			proxyHeader: "CF-Connecting-IP",
			trusted:     "172.17.0.1",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"CF-Connecting-IP": "2001:0DB8:0000:0000:0000:0000:0000:0001"},
			want:        "2001:db8::1",
			wantReason:  ManageIPReasonRightmostUntrusted,
		},
		{
			name:        "IPv4-mapped 写法归一成点分十进制",
			proxyHeader: "CF-Connecting-IP",
			trusted:     "172.17.0.1",
			remoteAddr:  "172.17.0.1:41234",
			headers:     map[string]string{"CF-Connecting-IP": "::ffff:1.2.3.4"},
			want:        "1.2.3.4",
			wantReason:  ManageIPReasonRightmostUntrusted,
		},
	}

	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			withManageIPConfig(t, cs.proxyHeader, cs.trusted, cs.cdnProvider, func() {
				trace := TraceManageClientIP(newManageCtx(cs.remoteAddr, cs.headers))
				if trace.ClientIP != cs.want {
					t.Errorf("ClientIP = %q, want %q (reason=%s)", trace.ClientIP, cs.want, trace.Reason)
				}
				if trace.Reason != cs.wantReason {
					t.Errorf("Reason = %q, want %q", trace.Reason, cs.wantReason)
				}
				if got := GetManageClientIP(newManageCtx(cs.remoteAddr, cs.headers)); got != trace.ClientIP {
					t.Errorf("GetManageClientIP = %q, 与 TraceManageClientIP 不一致 %q", got, trace.ClientIP)
				}
			})
		})
	}
}

// TestManageClientIPTraceFlags 诊断字段本身也要说得清：闸门过宽 / 头被整头丢弃
func TestManageClientIPTraceFlags(t *testing.T) {
	withManageIPConfig(t, "X-Forwarded-For", "0.0.0.0/0", "", func() {
		trace := TraceManageClientIP(newManageCtx("203.0.113.9:5555", map[string]string{"X-Forwarded-For": "1.2.3.4"}))
		if !trace.PeerTrusted || !trace.GateOverBroad {
			t.Errorf("PeerTrusted=%v GateOverBroad=%v，应为 true/true", trace.PeerTrusted, trace.GateOverBroad)
		}
		if len(trace.Headers) != 0 {
			t.Errorf("闸门过宽时不应解析任何头，实际 %+v", trace.Headers)
		}
	})
	withManageIPConfig(t, "X-Forwarded-For", "172.17.0.1", "", func() {
		long := strings.Repeat("1.2.3.4,", maxManageProxyHops+1) + "1.2.3.4"
		trace := TraceManageClientIP(newManageCtx("172.17.0.1:41234", map[string]string{"X-Forwarded-For": long}))
		if len(trace.Headers) != 1 || !trace.Headers[0].TooLong || len(trace.Headers[0].Hops) != 0 {
			t.Fatalf("超长头应标 TooLong 且不解析逐跳，实际 %+v", trace.Headers)
		}
		if len(trace.Headers[0].Value) > maxManageProxyHeaderEcho {
			t.Errorf("回显原文应截断到 %d，实际 %d", maxManageProxyHeaderEcho, len(trace.Headers[0].Value))
		}
		if trace.GateOverBroad {
			t.Error("172.17.0.1 是具体条目，GateOverBroad 应为 false")
		}
	})
}

// TestManageClientIPCDNProvider 引用 CDN 厂商时：回源段内的对端可信、段外伪造不采信
func TestManageClientIPCDNProvider(t *testing.T) {
	old := clientip.GetProviderRanges("cloudflare")
	defer clientip.SetProviderRanges("cloudflare", old)
	clientip.SetProviderRanges("cloudflare", ipset.BuildMatchSet([]string{"103.21.244.0/22"}))
	withManageIPConfig(t, "CF-Connecting-IP", "", "cloudflare", func() {
		trace := TraceManageClientIP(newManageCtx("103.21.244.10:1234", map[string]string{"CF-Connecting-IP": "1.2.3.4"}))
		if trace.ClientIP != "1.2.3.4" || trace.PeerTrustedBy != "cdn:cloudflare" {
			t.Errorf("回源段内应取头 1.2.3.4，实际 %q by=%q", trace.ClientIP, trace.PeerTrustedBy)
		}
		if trace.GateOverBroad {
			t.Error("CDN 回源段是具体条目，GateOverBroad 应为 false")
		}
		spoof := TraceManageClientIP(newManageCtx("8.8.8.8:1234", map[string]string{"CF-Connecting-IP": "1.2.3.4"}))
		if spoof.ClientIP != "8.8.8.8" || spoof.Reason != ManageIPReasonPeerUntrusted {
			t.Errorf("段外伪造应回退网络层，实际 %q reason=%q", spoof.ClientIP, spoof.Reason)
		}
	})
}

// TestManageClientIPTraceDetail 诊断信息本身要能说明"为什么取到这个值"
func TestManageClientIPTraceDetail(t *testing.T) {
	withManageIPConfig(t, "X-Forwarded-For", "10.0.0.0/8", "", func() {
		trace := TraceManageClientIP(newManageCtx("10.0.0.5:1234", map[string]string{"X-Forwarded-For": "6.6.6.6, 1.2.3.4, 10.0.0.5"}))
		if !trace.PeerTrusted || trace.PeerTrustedBy != "cidr:10.0.0.0/8" {
			t.Errorf("PeerTrusted=%v by=%q", trace.PeerTrusted, trace.PeerTrustedBy)
		}
		if len(trace.Headers) != 1 || !trace.Headers[0].Used || len(trace.Headers[0].Hops) != 3 {
			t.Fatalf("Headers = %+v", trace.Headers)
		}
		hops := trace.Headers[0].Hops
		if hops[0].Trusted || hops[1].Trusted || !hops[2].Trusted {
			t.Errorf("逐跳可信判定不符: %+v", hops)
		}
		if trace.ClientIP != "1.2.3.4" || trace.Reason != ManageIPReasonRightmostUntrusted {
			t.Errorf("ClientIP=%q reason=%q", trace.ClientIP, trace.Reason)
		}
	})
}

func TestManageTrustedProxiesHasOverBroad(t *testing.T) {
	cases := []struct {
		in    string
		want  bool
		entry string
	}{
		{"0.0.0.0/0", true, "0.0.0.0/0"},
		{"0.0.0.0/1", true, "0.0.0.0/1"},
		{"fc00::/7", false, ""},
		{"::/0", true, "::/0"},
		{"10.0.0.0/8, 0.0.0.0/0", true, "0.0.0.0/0"},
		{"10.0.0.0/8,172.16.0.0/12", false, ""},
		{"private", false, ""},
		{"", false, ""},
		{"172.17.0.1", false, ""},
	}
	for _, cs := range cases {
		got, entry := ManageTrustedProxiesHasOverBroad(cs.in)
		if got != cs.want || entry != cs.entry {
			t.Errorf("ManageTrustedProxiesHasOverBroad(%q) = %v,%q want %v,%q", cs.in, got, entry, cs.want, cs.entry)
		}
	}
}

func TestIsValidManageTrustedProxyEntry(t *testing.T) {
	valid := []string{"", "private", "PRIVATE", "10.0.0.0/8", "172.17.0.1", "fc00::/7", "::1"}
	invalid := []string{"10.0.0.0/33", "not-an-ip", "10.0.0.0/", "privatex"}
	for _, v := range valid {
		if !IsValidManageTrustedProxyEntry(v) {
			t.Errorf("%q 应判为合法", v)
		}
	}
	for _, v := range invalid {
		if IsValidManageTrustedProxyEntry(v) {
			t.Errorf("%q 应判为非法", v)
		}
	}
}
