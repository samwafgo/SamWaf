package accessgate

import "testing"

// TestNormalizeHostDefaultPortByScheme 是本次改造最危险的一条。
//
// 若默认端口的去除不看 scheme、一律去掉 :80 与 :443，
// HTTP 站点的 oa.x:443 与 HTTPS 站点的 oa.x 会归一化成同一个字符串，
// 于是它们的令牌互通 —— 比这次要修的 bug 严重得多。
func TestNormalizeHostDefaultPortByScheme(t *testing.T) {
	if a, b := NormalizeHost("oa.x:443", false), NormalizeHost("oa.x", true); a == b {
		t.Fatalf("HTTP 的 oa.x:443 与 HTTPS 的 oa.x 归一化成了同一个值 %q，令牌会跨站点互通", a)
	}
	if a, b := NormalizeHost("oa.x:80", true), NormalizeHost("oa.x", false); a == b {
		t.Fatalf("HTTPS 的 oa.x:80 与 HTTP 的 oa.x 归一化成了同一个值 %q", a)
	}
	// 与自身 scheme 匹配的默认端口才去掉
	if got := NormalizeHost("oa.x:80", false); got != "oa.x" {
		t.Fatalf("HTTP 下 :80 应去掉，got=%q", got)
	}
	if got := NormalizeHost("oa.x:443", true); got != "oa.x" {
		t.Fatalf("HTTPS 下 :443 应去掉，got=%q", got)
	}
}

func TestNormalizeHostCases(t *testing.T) {
	cases := []struct {
		in    string
		isTLS bool
		want  string
	}{
		{"OA.X:7013", false, "oa.x:7013"},
		{"  oa.x:7014  ", false, "oa.x:7014"},
		{"oa.x.", false, "oa.x"},
		{"oa.x.:7013", false, "oa.x:7013"},
		{"user@oa.x:7013", false, "oa.x:7013"},
		{"[::1]:8080", false, "[::1]:8080"},
		{"[::1]", false, "[::1]"},
		{"[::1]:80", false, "[::1]"},
		{"::1", false, "::1"},
		{"", false, ""},
		{"   ", false, ""},
	}
	for _, c := range cases {
		if got := NormalizeHost(c.in, c.isTLS); got != c.want {
			t.Errorf("NormalizeHost(%q,%v) = %q，期望 %q", c.in, c.isTLS, got, c.want)
		}
	}
}

// TestTokenCookieNamePerSite 同主机名不同端口必须派生出不同的 Cookie 名。
// 这正是「已登录却一直 401」的根因：Cookie 不区分端口，同名即互相覆盖。
func TestTokenCookieNamePerSite(t *testing.T) {
	a := TokenCookieName("samwaf_ac", NormalizeHost("oa.x:7013", false))
	b := TokenCookieName("samwaf_ac", NormalizeHost("oa.x:7014", false))
	if a == b {
		t.Fatalf("两个端口派生出了同一个 Cookie 名 %q，仍会互相覆盖", a)
	}
	// 稳定性：同一站点每次派生必须一致，否则用户随机掉线
	if a != TokenCookieName("samwaf_ac", NormalizeHost("OA.X:7013 ", false)) {
		t.Fatal("同一站点的 Cookie 名必须稳定")
	}
	// 前缀不变，stripAccessCookies 的剥离逻辑才不用改
	const want = "samwaf_ac_tk_"
	if len(a) != len(want)+16 || a[:len(want)] != want {
		t.Fatalf("Cookie 名格式不符：%q", a)
	}
	// 派生不出来时回退旧名，保持可用而不是把人锁在外面
	if got := TokenCookieName("samwaf_ac", ""); got != "samwaf_ac_tk" {
		t.Fatalf("空 host 应回退到旧名，got=%q", got)
	}
	if got := LegacyTokenCookieName(""); got != "samwaf_ac_tk" {
		t.Fatalf("LegacyTokenCookieName 空前缀应回落默认，got=%q", got)
	}
}

// TestNormalizeHostCollapsesDefaultPorts 记录一条**有意为之但很危险**的性质：
//
// 浏览器访问 http://oa.x/ 与 https://oa.x/ 都只发 Host: oa.x，
// 而 SamWaf 里 oa.x:80 与 oa.x:443 是两条独立的站点记录。
// 归一化之后它们的 host 串必然相同——这不是 bug，是 host 串本身
// 承载不了「是哪一条站点记录」这个信息。
//
// 所以令牌绑定绝不能只靠 host 串：真正区分站点的是 AccessToken.HostCode，
// 见 waf_access_session_service.go 的 matchBindings。
// 这条用例存在的意义是：如果哪天有人想「顺手」用 host 串当站点身份，
// 先来看看这里。
func TestNormalizeHostCollapsesDefaultPorts(t *testing.T) {
	httpSite := NormalizeHost("oa.x", false) // 浏览器访问 http://oa.x/
	httpsSite := NormalizeHost("oa.x", true) // 浏览器访问 https://oa.x/
	explicit80 := NormalizeHost("oa.x:80", false)
	explicit443 := NormalizeHost("oa.x:443", true)

	if httpSite != httpsSite || httpSite != explicit80 || httpSite != explicit443 {
		t.Fatalf("四种写法应当归一化到同一个 host 串，got %q/%q/%q/%q",
			httpSite, httpsSite, explicit80, explicit443)
	}
	if TokenCookieName("samwaf_ac", httpSite) != TokenCookieName("samwaf_ac", httpsSite) {
		t.Fatal("同一 host 串必然派生同一 Cookie 名")
	}
}
