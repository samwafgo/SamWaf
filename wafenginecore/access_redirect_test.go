package wafenginecore

import (
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"testing"
)

// newAccessTestEngine 造一个只有路由表的引擎，够 isManagedHost / validateReturnTo 用。
// 代理的站点：app.example.com:443、app.example.com:80、多域名绑定 alias.example.com:443、
// 泛域名 *.wild.example.com:443、宽松端口 noport.example.com。
func newAccessTestEngine() *WafEngine {
	waf := &WafEngine{}
	waf.InitRouting()
	waf.withWriteTable(func(nt *routingTable) {
		appHost := &wafenginmodel.HostSafe{Host: model.Hosts{Code: "app-code", Host: "app.example.com", Port: 443}}
		nt.HostTarget["app.example.com:443"] = appHost
		nt.HostTarget["app.example.com:80"] = appHost
		nt.HostCode["app-code"] = "app.example.com:443"

		nt.HostTargetMoreDomain["alias.example.com:443"] = "app-code"

		wildHost := &wafenginmodel.HostSafe{Host: model.Hosts{Code: "wild-code", Host: "*.wild.example.com", Port: 443}}
		nt.HostTarget["*.wild.example.com:443"] = wildHost
		nt.HostCode["wild-code"] = "*.wild.example.com:443"

		nt.HostTargetNoPort["noport.example.com"] = "noport.example.com:443"
		nt.HostTarget["noport.example.com:443"] = &wafenginmodel.HostSafe{
			Host: model.Hosts{Code: "noport-code", Host: "noport.example.com", Port: 443},
		}
	})
	return waf
}

// TestValidateReturnToRejectsOpenRedirect 是这套认证网关最关键的一个单测。
//
// 认证网关必然要"认证成功后把用户送回他原本想去的地方"，而那个地址来自请求，
// 所以它天然是开放重定向的高危点。任何一条用例回归，都意味着攻击者可以用一个
// 看起来完全合法的本站 URL 把受害者钓到自己的服务器上。
func TestValidateReturnToRejectsOpenRedirect(t *testing.T) {
	waf := newAccessTestEngine()
	const expect = "app.example.com:443"

	bad := []struct {
		name string
		raw  string
	}{
		{"协议相对地址", "//evil.com/x"},
		{"反斜杠伪协议相对地址", "\\\\evil.com/x"},
		{"混合斜杠", "/\\evil.com"},
		{"userinfo 伪装", "https://app.example.com:443@evil.com/x"},
		{"userinfo 伪装(无端口)", "https://app.example.com@evil.com/"},
		{"后缀同形域名", "https://app.example.com.evil.com/x"},
		{"前缀同形域名", "https://evilapp.example.com/x"},
		{"完全不同的域名", "https://evil.com/x"},
		{"CR 注入", "https://app.example.com:443/x\rSet-Cookie:a=b"},
		{"LF 注入", "https://app.example.com:443/x\nSet-Cookie:a=b"},
		{"TAB 注入", "https://app.example.com:443/\tx"},
		{"NUL 字节", "https://app.example.com:443/\x00"},
		{"javascript 伪协议", "javascript:alert(1)"},
		{"data 伪协议", "data:text/html,<script>alert(1)</script>"},
		{"file 协议", "file:///etc/passwd"},
		{"空字符串", ""},
		{"仅路径(缺少域名绑定，无法确认目标)", "/foo"},
		{"未被本 WAF 代理的域名", "https://other.example.org/x"},
		{"域名对但端口不符(票据绑的是 443)", "https://app.example.com:8443/x"},
	}
	for _, c := range bad {
		t.Run("拒绝-"+c.name, func(t *testing.T) {
			if got, ok := waf.validateReturnTo(c.raw, expect); ok {
				t.Fatalf("validateReturnTo(%q) 本应被拒绝，却放行为 %q", c.raw, got)
			}
		})
	}
}

// TestValidateReturnToRejectsOverLongURL 超长地址直接拒，避免被当成载荷投递通道。
func TestValidateReturnToRejectsOverLongURL(t *testing.T) {
	waf := newAccessTestEngine()
	long := "https://app.example.com:443/"
	for len(long) <= maxReturnToLen {
		long += "aaaaaaaaaa"
	}
	if _, ok := waf.validateReturnTo(long, "app.example.com:443"); ok {
		t.Fatal("超过长度上限的回跳地址应被拒绝")
	}
}

// TestValidateReturnToBindsToTicketHost 回跳目标必须等于票据里记录的域名，
// 而不是"任意一个本 WAF 代理的域名"。
//
// 这是"双重收窄"的第一重：即使 WAF 代理了 100 个站点，从 a 站发起的认证也只能回到 a 站。
// 少了它，攻击者可以在自己控制的受管站点上发起认证，再把受害者的票据换到别的站点去用。
func TestValidateReturnToBindsToTicketHost(t *testing.T) {
	waf := newAccessTestEngine()
	// alias.example.com 确实由本 WAF 代理（HostTargetMoreDomain 里有），
	// 但票据绑定的是 app.example.com，所以必须拒绝。
	if _, ok := waf.validateReturnTo("https://alias.example.com/x", "app.example.com:443"); ok {
		t.Fatal("回跳到另一个受管域名也必须拒绝——目标必须与票据绑定的域名完全一致")
	}
}

func TestValidateReturnToAcceptsLegit(t *testing.T) {
	waf := newAccessTestEngine()
	cases := []struct {
		name, raw, expectHost, want string
	}{
		{"带端口的完整地址", "https://app.example.com:443/foo?x=1", "app.example.com:443", "https://app.example.com:443/foo?x=1"},
		{"大小写不敏感", "https://APP.example.com:443/foo", "app.example.com:443", "https://APP.example.com:443/foo"},
		{"空路径补成根", "https://app.example.com:443", "app.example.com:443", "https://app.example.com:443/"},
		{"http 站点", "http://app.example.com:80/bar", "app.example.com:80", "http://app.example.com:80/bar"},
		{"多域名绑定", "https://alias.example.com:443/x", "alias.example.com:443", "https://alias.example.com:443/x"},
		{"宽松端口站点(不带端口)", "https://noport.example.com/x", "noport.example.com", "https://noport.example.com/x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := waf.validateReturnTo(c.raw, c.expectHost)
			if !ok {
				t.Fatalf("validateReturnTo(%q, %q) 本应放行却被拒", c.raw, c.expectHost)
			}
			if got != c.want {
				t.Fatalf("validateReturnTo(%q) = %q, 期望 %q", c.raw, got, c.want)
			}
		})
	}
}

// TestValidateReturnToStripsFragment 片段对服务端无意义，且是 XSS 载荷常见藏身处。
func TestValidateReturnToStripsFragment(t *testing.T) {
	waf := newAccessTestEngine()
	got, ok := waf.validateReturnTo("https://app.example.com:443/foo#<script>", "app.example.com:443")
	if !ok {
		t.Fatal("带片段的合法地址应被放行(片段剥离后)")
	}
	if got != "https://app.example.com:443/foo" {
		t.Fatalf("片段未被剥离: %q", got)
	}
}

func TestIsManagedHost(t *testing.T) {
	waf := newAccessTestEngine()
	cases := []struct {
		host string
		want bool
	}{
		{"app.example.com:443", true},
		{"app.example.com:80", true},
		{"app.example.com", true}, // 不带端口时按 443/80 各试一次
		{"alias.example.com:443", true},
		{"noport.example.com", true},
		{"noport.example.com:9999", true}, // 宽松端口站点，任何端口都受管
		{"anything.wild.example.com:443", true},
		{"evil.com", false},
		{"evil.com:443", false},
		{"app.example.com.evil.com", false},
		{"", false},
	}
	for _, c := range cases {
		if got := waf.isManagedHost(c.host); got != c.want {
			t.Fatalf("isManagedHost(%q) = %v, 期望 %v", c.host, got, c.want)
		}
	}
}

// TestIsManagedHostEmptyTable 路由表还没发布时不能 panic，也不能把一切都判成受管。
func TestIsManagedHostEmptyTable(t *testing.T) {
	waf := &WafEngine{}
	if waf.isManagedHost("app.example.com") {
		t.Fatal("空路由表下不应判定任何域名为受管")
	}
}

// TestIsManagedHostIgnoresCatchAll 回归测试：配置了「不指定域名」的通配站点时，
// isManagedHost 曾经对任意域名都返回 true。
//
// 后果很严重：validateReturnTo 的绑定层比对的是「票据里记录的域名」，
// 而那个域名来自攻击者可控的 Host 头。通配站点让任意 Host 都能命中路由表，
// 于是绑定层与路由表层同时失效 —— 攻击者能让 WAF 自己签出一个指向 evil.com
// 的合法跳转，拿认证中心域名当跳板钓鱼，并把一次性票据明文送进自己的日志。
func TestIsManagedHostIgnoresCatchAll(t *testing.T) {
	waf := &WafEngine{}
	waf.InitRouting()
	waf.withWriteTable(func(nt *routingTable) {
		catchAll := &wafenginmodel.HostSafe{Host: model.Hosts{Code: "any-code", Host: "*", Port: 80}}
		nt.HostTargetNoPort["*"] = "*:80"
		nt.HostTarget["*:80"] = catchAll
		nt.HostTarget["*:443"] = catchAll
		nt.HostCode["any-code"] = "*:80"
	})

	for _, h := range []string{"evil.com", "evil.com:443", "anything.example.org"} {
		if waf.isManagedHost(h) {
			t.Fatalf("通配站点不应让任意域名(%q)被判定为受管——那会让开放重定向防护整体失效", h)
		}
	}

	// 回跳校验也必须一并拒绝
	if _, ok := waf.validateReturnTo("https://evil.com/x", "evil.com"); ok {
		t.Fatal("即使存在通配站点，也不能回跳到任意域名")
	}
}
