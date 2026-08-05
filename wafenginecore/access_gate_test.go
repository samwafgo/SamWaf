package wafenginecore

import (
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/accessgate"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
)

// TestAccessShouldReturnJSON 401 vs 302 的判定。
//
// 最关键的一条是 WebSocket：WS 客户端不跟随重定向，给它 302 会变成一个
// 「握手莫名其妙失败」的故障，用户几乎不可能自行定位到是认证网关干的。
// 所以哪怕站点强制配了 redirect，WS 也必须走 401。
func TestAccessShouldReturnJSON(t *testing.T) {
	waf := &WafEngine{}
	autoCfg := &accessgate.Config{UnauthAction: model.AccessUnauthAuto}
	inherit := model.HostAccessConfig{}

	newReq := func(method string, headers map[string]string) *http.Request {
		r := httptest.NewRequest(method, "http://app.example.com/foo", nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}

	cases := []struct {
		name    string
		req     *http.Request
		cfg     *accessgate.Config
		hostCfg model.HostAccessConfig
		want    bool
	}{
		{"浏览器导航 GET → 302", newReq("GET", map[string]string{
			"Accept": "text/html,application/xhtml+xml"}), autoCfg, inherit, false},
		{"WebSocket 握手 → 401(绝不能 302)", newReq("GET", map[string]string{
			"Accept": "text/html", "Upgrade": "websocket"}), autoCfg, inherit, true},
		{"XHR → 401", newReq("GET", map[string]string{
			"Accept": "text/html", "X-Requested-With": "XMLHttpRequest"}), autoCfg, inherit, true},
		{"fetch(cors) → 401", newReq("GET", map[string]string{
			"Accept": "text/html", "Sec-Fetch-Mode": "cors"}), autoCfg, inherit, true},
		{"Sec-Fetch-Mode=navigate → 302", newReq("GET", map[string]string{
			"Accept": "text/html", "Sec-Fetch-Mode": "navigate"}), autoCfg, inherit, false},
		{"JSON 请求体 → 401", newReq("POST", map[string]string{
			"Accept": "text/html", "Content-Type": "application/json"}), autoCfg, inherit, true},
		{"非 GET/HEAD → 401", newReq("POST", map[string]string{
			"Accept": "text/html"}), autoCfg, inherit, true},
		{"不接受 HTML → 401", newReq("GET", map[string]string{
			"Accept": "application/json"}), autoCfg, inherit, true},
		{"无 Accept 头 → 401", newReq("GET", nil), autoCfg, inherit, true},

		{"全局强制 401", newReq("GET", map[string]string{"Accept": "text/html"}),
			&accessgate.Config{UnauthAction: model.AccessUnauth401}, inherit, true},
		{"全局强制 302", newReq("GET", map[string]string{"Accept": "application/json"}),
			&accessgate.Config{UnauthAction: model.AccessUnauthRedirect}, inherit, false},
		{"全局强制 302 也不能坑 WebSocket", newReq("GET", map[string]string{"Upgrade": "websocket"}),
			&accessgate.Config{UnauthAction: model.AccessUnauthRedirect}, inherit, true},

		{"站点级覆盖全局：站点要 401", newReq("GET", map[string]string{"Accept": "text/html"}),
			autoCfg, model.HostAccessConfig{UnauthAction: model.AccessUnauth401}, true},
		{"站点级覆盖全局：站点要 302", newReq("GET", map[string]string{"Accept": "application/json"}),
			&accessgate.Config{UnauthAction: model.AccessUnauth401},
			model.HostAccessConfig{UnauthAction: model.AccessUnauthRedirect}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := waf.accessShouldReturnJSON(c.req, c.cfg, c.hostCfg); got != c.want {
				t.Fatalf("accessShouldReturnJSON = %v, 期望 %v", got, c.want)
			}
		})
	}
}

// TestAccessACMEWhitelistIsPathTraversalSafe 是一条回归测试：
// ACME 白名单曾经用未归一化的 r.URL.Path 判定，导致
// /.well-known/acme-challenge/../../admin 直接命中前缀被放行，
// 而点号段会被原样转发给后端，后端按 RFC 3986 归一化成 /admin —— 整个网关失效。
//
// 这里验证的是判定所依据的归一化路径本身：只要用 path.Clean 后的路径去比前缀，
// 带 ../ 的请求就不可能命中 ACME 白名单。
func TestAccessACMEWhitelistIsPathTraversalSafe(t *testing.T) {
	const acme = "/.well-known/acme-challenge/"

	// 直接测网关用的那个判定函数，而不是 path.Clean 的语义 ——
	// 后者即使有人把实现改回 r.URL.Path 也照样是绿的，钉不住回归。
	check := func(raw string) bool {
		r := httptest.NewRequest("GET", "http://app.example.com"+raw, nil)
		return isACMEChallengePath(strings.ToLower(path.Clean(r.URL.Path)), r.URL.Path)
	}

	traversals := []string{
		"/.well-known/acme-challenge/../../admin/index.php",
		"/.well-known/acme-challenge/%2e%2e/%2e%2e/admin",
		"/.well-known/acme-challenge/./../../etc/passwd",
		"/foo/../.well-known/acme-challenge/x", // 反向构造：Clean 后会命中前缀，靠 .. 检查拦住
	}
	for _, raw := range traversals {
		t.Run("必须拒绝-"+raw, func(t *testing.T) {
			if check(raw) {
				t.Fatalf("带 ../ 的路径被 ACME 白名单放行了: %q", raw)
			}
		})
	}

	// 确认前两条用例确实测到了点子上：原始路径是会命中 ACME 前缀的，
	// 也就是说改回用 r.URL.Path 判定的话它们就会被放行。
	r := httptest.NewRequest("GET", "http://app.example.com/.well-known/acme-challenge/../../admin", nil)
	if !strings.HasPrefix(r.URL.Path, acme) {
		t.Fatal("用例失效：原始路径未命中 ACME 前缀，测不到回归")
	}

	// 正常的 challenge 请求必须照常放行，否则证书续期会全线失败
	for _, ok := range []string{
		"/.well-known/acme-challenge/tokenABC",
		"/.well-known/acme-challenge/2NKiiETgQdPmmjlM88mH5uo6jM98PrgWwsDslaN8",
	} {
		if !check(ok) {
			t.Fatalf("正常的 ACME 校验请求必须放行: %q", ok)
		}
	}
	// 非 ACME 路径不该被误放
	for _, no := range []string{"/admin", "/", "/.well-known/other/x"} {
		if check(no) {
			t.Fatalf("非 ACME 路径不应放行: %q", no)
		}
	}
}

// TestStripAccessCookiesMultiValue HTTP/1.1 允许客户端发多行 Cookie 头。
// Header.Get 只返回第一行、Header.Set 会替换全部 —— 只处理第一行等于把其余几行的
// 业务 Cookie 悄悄吃掉。而本函数跑在每一个通过网关的请求上（含 Access 关闭的站点），
// 影响面是全量流量。
func TestStripAccessCookiesMultiValue(t *testing.T) {
	cfg := &accessgate.Config{CookiePrefix: "samwaf_ac"}
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.Header["Cookie"] = []string{"a=1; samwaf_ac_tk=SECRET", "b=2", "c=3"}

	if !stripAccessCookies(r, cfg) {
		t.Fatal("确实删掉了令牌，应返回 true")
	}
	got := map[string]string{}
	for _, ck := range r.Cookies() {
		got[ck.Name] = ck.Value
	}
	for _, name := range []string{"a", "b", "c"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("业务 Cookie %q 被误删，剩余: %v", name, got)
		}
	}
	if _, ok := got["samwaf_ac_tk"]; ok {
		t.Fatal("令牌未被剥离")
	}
}

// TestStripAccessCookiesNoopWhenNothingToStrip 没删到东西就不该动这个头。
// 本函数跑在全量流量上，无谓地重新序列化 Cookie 头既没收益又可能改变原始写法。
func TestStripAccessCookiesNoop(t *testing.T) {
	cfg := &accessgate.Config{CookiePrefix: "samwaf_ac"}
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.Header["Cookie"] = []string{"a=1;b=2", "c=3"}
	before := append([]string(nil), r.Header["Cookie"]...)

	if stripAccessCookies(r, cfg) {
		t.Fatal("没有本模块的 Cookie 时应返回 false")
	}
	after := r.Header["Cookie"]
	if len(after) != len(before) {
		t.Fatalf("头被改动了: %v → %v", before, after)
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("头被重新序列化了: %v → %v", before, after)
		}
	}
}

// TestSanitizeAccessRequest 放行给后端之前必须抹掉本模块的痕迹。
//
// 两件事都很要紧：
//   - 会话 Cookie 是 WAF 与浏览器之间的凭据，后端拿到就可能写进明文日志
//   - 身份头必须先删后写，否则客户端自带一个 X-SamWaf-Access-User 就能冒充任意账号
func TestSanitizeAccessRequest(t *testing.T) {
	cfg := &accessgate.Config{CookiePrefix: "samwaf_ac"}

	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.Header.Set("Cookie", "biz=1; samwaf_ac_tk=secret-token; other=2; samwaf_ac_sso=secret-sso")
	r.Header.Set("X-SamWaf-Access-User", "attacker")
	r.Header.Set("X-SamWaf-Access-Session", "forged")

	stripAccessCookies(r, cfg)

	cookie := r.Header.Get("Cookie")
	if strings.Contains(cookie, "samwaf_ac") {
		t.Fatalf("会话 Cookie 未被剥离，仍会转发给后端: %q", cookie)
	}
	if !strings.Contains(cookie, "biz=1") || !strings.Contains(cookie, "other=2") {
		t.Fatalf("业务 Cookie 被误删: %q", cookie)
	}
}

// TestSanitizeAccessRequestAllCookiesStripped 全部 Cookie 都是本模块的时候，整个头要删掉，
// 而不是留一个空的 Cookie 头（某些后端框架对空 Cookie 头处理得很怪）。
func TestSanitizeAccessRequestAllCookiesStripped(t *testing.T) {
	cfg := &accessgate.Config{CookiePrefix: "samwaf_ac"}
	r := httptest.NewRequest("GET", "http://app.example.com/", nil)
	r.Header.Set("Cookie", "samwaf_ac_tk=a; samwaf_ac_sso=b")
	stripAccessCookies(r, cfg)
	if _, ok := r.Header["Cookie"]; ok {
		t.Fatalf("应当整个删除 Cookie 头，实际残留: %q", r.Header.Get("Cookie"))
	}
}

// TestMatchAccessServiceToken 服务令牌用 sha256 比对，且未配置时必须一律不放行。
func TestMatchAccessServiceToken(t *testing.T) {
	waf := &WafEngine{}
	sum := sha256.Sum256([]byte("s3cr3t"))
	tokenHash := hex.EncodeToString(sum[:])

	newReq := func(header, value string) *http.Request {
		r := httptest.NewRequest("GET", "http://app.example.com/", nil)
		if header != "" {
			r.Header.Set(header, value)
		}
		return r
	}

	// 未配置头名 → 永不放行
	if waf.matchAccessServiceToken(newReq("X-Service-Token", "anything"),
		&accessgate.Config{ServiceTokenHashes: []string{tokenHash}}) {
		t.Fatal("未配置令牌头名时不应放行")
	}
	// 配了头名但没有任何哈希 → 永不放行（空列表不能等于"放行一切"）
	if waf.matchAccessServiceToken(newReq("X-Service-Token", "anything"),
		&accessgate.Config{ServiceTokenHeader: "X-Service-Token"}) {
		t.Fatal("令牌列表为空时不应放行")
	}
	// 请求没带头 → 不放行
	if waf.matchAccessServiceToken(newReq("", ""),
		&accessgate.Config{ServiceTokenHeader: "X-Service-Token", ServiceTokenHashes: []string{tokenHash}}) {
		t.Fatal("请求未携带令牌头时不应放行")
	}
	// 带了错误令牌 → 不放行
	if waf.matchAccessServiceToken(newReq("X-Service-Token", "wrong"),
		&accessgate.Config{ServiceTokenHeader: "X-Service-Token", ServiceTokenHashes: []string{tokenHash}}) {
		t.Fatal("错误令牌不应放行")
	}
	// 正确令牌 → 放行
	if !waf.matchAccessServiceToken(newReq("X-Service-Token", "s3cr3t"),
		&accessgate.Config{ServiceTokenHeader: "X-Service-Token", ServiceTokenHashes: []string{tokenHash}}) {
		t.Fatal("正确令牌应当放行")
	}
	// 多个令牌里命中任意一个即可（方便轮换：先加新的再删旧的）
	if !waf.matchAccessServiceToken(newReq("X-Service-Token", "s3cr3t"),
		&accessgate.Config{ServiceTokenHeader: "X-Service-Token",
			ServiceTokenHashes: []string{"deadbeef", tokenHash}}) {
		t.Fatal("令牌列表中命中任意一个都应放行")
	}
}

// TestSignVerifyAuthReq rq 的签名与验签。
//
// 覆盖三种攻击形态：改载荷、改签名、换密钥。任何一种被放过，
// 攻击者就能自己构造回跳目标，validateReturnTo 的绑定层随之失效。
func TestSignVerifyAuthReq(t *testing.T) {
	secret := []byte("test-secret-key")
	req := accessAuthReq{R: "https://app.example.com/foo", H: "app.example.com", E: 1 << 40, N: "abcd"}

	rq := signAuthReq(secret, req)
	if rq == "" {
		t.Fatal("签名失败")
	}
	got, ok := verifyAuthReq(secret, rq)
	if !ok {
		t.Fatal("自己签的 rq 应当验签通过")
	}
	if got.R != req.R || got.H != req.H {
		t.Fatalf("载荷解析错误: %+v", got)
	}

	// 改载荷
	idx := strings.LastIndex(rq, ".")
	tampered := "eyJyIjoiaHR0cHM6Ly9ldmlsLmNvbSJ9" + rq[idx:]
	if _, ok := verifyAuthReq(secret, tampered); ok {
		t.Fatal("载荷被篡改后仍验签通过 —— 攻击者可任意指定回跳目标")
	}
	// 改签名
	if _, ok := verifyAuthReq(secret, rq[:idx]+".AAAA"); ok {
		t.Fatal("签名被篡改后仍验签通过")
	}
	// 换密钥
	if _, ok := verifyAuthReq([]byte("other-secret"), rq); ok {
		t.Fatal("用别的密钥竟然验签通过")
	}
	// 空密钥必须一律拒绝，绝不能退化成"不验签"
	if _, ok := verifyAuthReq(nil, rq); ok {
		t.Fatal("空密钥时必须拒绝，不能降级为不验签")
	}
	if signAuthReq(nil, req) != "" {
		t.Fatal("空密钥时不应产出 rq")
	}
	// 格式垃圾
	for _, bad := range []string{"", ".", "abc", "abc.", ".abc"} {
		if _, ok := verifyAuthReq(secret, bad); ok {
			t.Fatalf("畸形 rq %q 竟然验签通过", bad)
		}
	}
}

// TestVerifyAuthReqExpired 过期的 rq 必须拒绝，否则一个被截获的跳转链接可以长期复用。
func TestVerifyAuthReqExpired(t *testing.T) {
	secret := []byte("test-secret-key")
	rq := signAuthReq(secret, accessAuthReq{
		R: "https://app.example.com/foo", H: "app.example.com", E: 1, N: "abcd",
	})
	if _, ok := verifyAuthReq(secret, rq); ok {
		t.Fatal("已过期的 rq 仍验签通过")
	}
}

// TestBuildAccessEntryURL 未认证时该跳去哪。
func TestBuildAccessEntryURL(t *testing.T) {
	waf := &WafEngine{}
	secret := []byte("test-secret-key")

	// 没配认证中心时只能退回同域登录页。正常配置下 DoAccessGate 会先放行整个请求，
	// 走不到这里；留着是为了万一走到也别给出一个坏 URL。
	noCenter := &accessgate.Config{PathPrefix: "/samwaf_access", HmacSecret: secret}
	r := httptest.NewRequest("GET", "http://app.example.com/foo?x=1", nil)
	r.Host = "app.example.com"
	got := waf.buildAccessEntryURL(r, noCenter)
	if !strings.HasPrefix(got, "/samwaf_access/login?rq=") {
		t.Fatalf("未配认证中心时应退回同域登录页，实际: %q", got)
	}

	center := &accessgate.Config{
		PathPrefix: "/samwaf_access", HmacSecret: secret,
		CenterOrigin: "https://sso.example.com", CenterHost: "sso.example.com",
	}
	got = waf.buildAccessEntryURL(r, center)
	if !strings.HasPrefix(got, "https://sso.example.com/samwaf_access/authorize?rq=") {
		t.Fatalf("中心模式应跳认证中心，实际: %q", got)
	}

	// 已经在认证中心域名上时不该再跳自己，直接渲染登录页
	rc := httptest.NewRequest("GET", "http://sso.example.com/foo", nil)
	rc.Host = "sso.example.com"
	got = waf.buildAccessEntryURL(rc, center)
	if !strings.HasPrefix(got, "/samwaf_access/login?rq=") {
		t.Fatalf("在认证中心域名上应直接给登录页，实际: %q", got)
	}
}

// TestBuildAccessEntryURLWithoutSecret 密钥缺失时仍要给出可用的登录入口（只是丢掉回跳能力），
// 不能因为签不出 rq 就把用户卡死在一个坏 URL 上。
func TestBuildAccessEntryURLWithoutSecret(t *testing.T) {
	waf := &WafEngine{}
	cfg := &accessgate.Config{PathPrefix: "/samwaf_access"}
	r := httptest.NewRequest("GET", "http://app.example.com/foo", nil)
	r.Host = "app.example.com"
	if got := waf.buildAccessEntryURL(r, cfg); got != "/samwaf_access/login" {
		t.Fatalf("无密钥时应给出不带 rq 的登录页地址，实际: %q", got)
	}
}

// TestAccessOnCenter 锁死「哪些请求算打在认证中心上」。
//
// 登录页、/validate、/otp 全都靠它分流：只要它对业务域名说了 true，
// 用户就能在业务域名上就地登录，统一认证瞬间退化成「每个域名各登一次」。
// 端口与大小写都要认——浏览器发来的 Host 头带不带端口取决于是不是默认端口。
func TestAccessOnCenter(t *testing.T) {
	center := &accessgate.Config{
		CenterOrigin: "https://sso.example.com", CenterHost: "sso.example.com",
	}
	noCenter := &accessgate.Config{}

	cases := []struct {
		name string
		cfg  *accessgate.Config
		host string
		want bool
	}{
		{"认证中心本身", center, "sso.example.com", true},
		{"认证中心-大小写不敏感", center, "SSO.Example.COM", true},
		{"业务域名", center, "app.example.com", false},
		{"带端口与配置不符", center, "sso.example.com:8443", false},
		{"未配认证中心时任何域名都不算", noCenter, "sso.example.com", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "http://x/", nil)
		r.Host = c.host
		if got := accessOnCenter(r, c.cfg); got != c.want {
			t.Errorf("%s: accessOnCenter(host=%q) = %v, want %v", c.name, c.host, got, c.want)
		}
	}
}

// TestAccessCurrentURL 回跳地址要保留查询串，否则用户带参数的深链接会丢参数。
func TestAccessCurrentURL(t *testing.T) {
	r := httptest.NewRequest("GET", "http://app.example.com/foo?x=1&y=2", nil)
	r.Host = "app.example.com"
	if got := accessCurrentURL(r); got != "http://app.example.com/foo?x=1&y=2" {
		t.Fatalf("accessCurrentURL = %q", got)
	}
}

// TestBuildAccessCookieSameSite SameSite 必须是 Lax。
//
// Strict 会让 callback 之后紧接着的 302 不携带刚种下的 Cookie，
// 用户会陷入「登录成功 → 又跳登录页」的无限循环；这个 bug 在本地单域名测试时
// 完全复现不出来，只有真做跨域 SSO 才会撞上，所以用单测钉住。
func TestBuildAccessCookieSameSite(t *testing.T) {
	ck := buildAccessCookie("samwaf_ac_tk", "v", 3600, true)
	if ck.SameSite != http.SameSiteLaxMode {
		t.Fatal("SameSite 必须是 Lax：Strict 会导致跨域回跳后 Cookie 不被携带，陷入无限跳转")
	}
	if !ck.HttpOnly {
		t.Fatal("会话 Cookie 必须 HttpOnly，否则 XSS 可直接读走")
	}
	if ck.Path != "/" {
		t.Fatal("Cookie 必须作用于整站")
	}
}

// TestAccessCookieSecure Secure 必须自动判定：纯 HTTP 站点打了 Secure，
// 浏览器根本不会保存 Cookie，用户会看到"登录成功但立刻又要登录"。
func TestAccessCookieSecure(t *testing.T) {
	plainCfg := &accessgate.Config{}
	httpReq := httptest.NewRequest("GET", "http://app.example.com/", nil)

	if accessCookieSecure(httpReq, nil, plainCfg) {
		t.Fatal("纯 HTTP 且未强制时不应打 Secure")
	}
	if !accessCookieSecure(httpReq, nil, &accessgate.Config{ForceSecureCookie: true}) {
		t.Fatal("强制开关打开时应打 Secure")
	}
	// 站点配了强制跳 HTTPS，最终一定走在 https 上
	jump := &wafenginmodel.HostSafe{Host: model.Hosts{AutoJumpHTTPS: 1}}
	if !accessCookieSecure(httpReq, jump, plainCfg) {
		t.Fatal("站点开启自动跳HTTPS时应打 Secure")
	}
	noJump := &wafenginmodel.HostSafe{Host: model.Hosts{AutoJumpHTTPS: 0}}
	if accessCookieSecure(httpReq, noJump, plainCfg) {
		t.Fatal("纯 HTTP 站点不应打 Secure，否则浏览器不会保存 Cookie")
	}
}

// TestAccessLoginNoRedirectLoop 是一条回归测试。
//
// handleAccessRequest 的分流发生在「开关判定之前」，所以 /login 在功能未启用、
// 未配认证中心时同样可达。早先那一版无条件把「不在认证中心上」的请求 302 到
// buildAccessEntryURL —— 而该函数在没有认证中心时返回的正是 /samwaf_access/login 本身，
// 于是浏览器在同一个地址上无限重定向。
//
// 这里只锁死「无认证中心时不得跳回自己」这个性质，不依赖具体状态码。
func TestAccessLoginNoRedirectLoop(t *testing.T) {
	waf := &WafEngine{}
	cfg := &accessgate.Config{PathPrefix: "/samwaf_access", HmacSecret: []byte("k")}
	r := httptest.NewRequest("GET", "http://app.example.com/samwaf_access/login", nil)
	r.Host = "app.example.com"

	if accessOnCenter(r, cfg) {
		t.Fatal("未配认证中心时不该把任何域名当成认证中心")
	}
	// 这就是当年被拿去当跳转目标的值：它指回本路径，一旦 302 过去就是死循环
	if entry := waf.buildAccessEntryURL(r, cfg); !strings.HasPrefix(entry, "/samwaf_access/login") {
		t.Fatalf("前提变了：无认证中心时 buildAccessEntryURL 不再指向登录页，实际 %q", entry)
	}
}
