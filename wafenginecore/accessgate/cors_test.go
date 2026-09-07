package accessgate

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNormalizeOriginRejects 非法 Origin 必须在解析阶段就被丢掉。
//
// 其中 null 与 * 是安全项而非健壮性项：
// null 来自 sandbox iframe / data: / file://，放进白名单等于对任意攻击页面开放；
// * 与 Allow-Credentials:true 是规范禁止的组合。
func TestNormalizeOriginRejects(t *testing.T) {
	bad := []string{
		"", "   ", "*", "null", "NULL",
		"oa.x:7013",
		"ftp://oa.x",
		"http://oa.x/",
		"http://oa.x/api",
		"http://oa.x?a=1",
		"http://oa.x#f",
		"http://oa.x\\evil.com",
		"http://oa.x\r\nX-Evil: 1",
		"http://" + strings.Repeat("a", 600),
	}
	for _, item := range bad {
		if got := normalizeOrigin(item); got != "" {
			t.Errorf("normalizeOrigin(%q) = %q，期望被丢弃", item, got)
		}
	}
	good := map[string]string{
		"http://oa.x:7013":  "http://oa.x:7013",
		" HTTPS://OA.X ":    "https://oa.x",
		"https://a.b.oa.x":  "https://a.b.oa.x",
		"http://[::1]:8080": "http://[::1]:8080",
	}
	for in, want := range good {
		if got := normalizeOrigin(in); got != want {
			t.Errorf("normalizeOrigin(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// TestMatchOriginIsExact 是本次改造最重要的一条回归。
//
// 任何前缀/后缀/包含式匹配都能被下面这些构造命中，
// 命中即意味着任意站点拿到了对受保护接口的带凭据跨源读权。
func TestMatchOriginIsExact(t *testing.T) {
	allow := BuildAllowOrigins("http://oa.x:7013\nhttps://app.oa.x")

	attack := []string{
		"http://oa.x:7013.evil.com",
		"http://evil.com/?http://oa.x:7013",
		"http://oa.x:7013evil.com",
		"http://evil.http://oa.x:7013",
		"http://oa.x",
		"http://oa.x:9999",
		"https://oa.x:7013",
		"http://xoa.x:7013",
		"null",
		"*",
		"",
	}
	for _, o := range attack {
		if got, ok := MatchOrigin(o, allow); ok {
			t.Errorf("MatchOrigin(%q) 命中了 %q，白名单是精确比对不该命中", o, got)
		}
	}

	// 命中时必须返回白名单侧的值，而不是把请求头原样回显
	got, ok := MatchOrigin("HTTP://OA.X:7013", allow)
	if !ok || got != "http://oa.x:7013" {
		t.Fatalf("命中后应返回白名单侧的值，got=%q ok=%v", got, ok)
	}
}

// TestBuildAllowOriginsLimits 条数上限与去重：白名单是热路径 O(n) 遍历，
// 不封顶就能被配置成 CPU 放大器。
func TestBuildAllowOriginsLimits(t *testing.T) {
	var b strings.Builder
	for i := 0; i < corsMaxOrigins*3; i++ {
		b.WriteString("http://h")
		b.WriteString(strings.Repeat("a", i%5+1))
		b.WriteString(".x:1\n")
	}
	if n := len(BuildAllowOrigins(b.String())); n > corsMaxOrigins {
		t.Fatalf("白名单条数 %d 超过上限 %d", n, corsMaxOrigins)
	}
	if got := BuildAllowOrigins("http://a.x\nhttp://a.x\nHTTP://A.X"); len(got) != 1 {
		t.Fatalf("重复条目应去重，got=%v", got)
	}
	if got := BuildAllowOrigins("  \n\n , ,"); got != nil {
		t.Fatalf("全空输入应返回 nil，got=%v", got)
	}
}

// TestRequestOriginMultiHeader 多个 Origin 头必须判无效，不能取第一个。
func TestRequestOriginMultiHeader(t *testing.T) {
	h := http.Header{}
	if RequestOrigin(h) != "" {
		t.Fatal("无 Origin 头应返回空")
	}
	h.Add("Origin", "http://oa.x:7013")
	if RequestOrigin(h) != "http://oa.x:7013" {
		t.Fatal("单个 Origin 头应正常返回")
	}
	h.Add("Origin", "http://evil.com")
	if got := RequestOrigin(h); got != "" {
		t.Fatalf("多个 Origin 头必须判无效，got=%q", got)
	}
}

// TestIsPreflight 三个条件缺一不可，否则普通 OPTIONS 业务请求会被误代答。
func TestIsPreflight(t *testing.T) {
	mk := func(method string, headers map[string]string) *http.Request {
		r := httptest.NewRequest(method, "http://oa.x:7014/api", nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	cases := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{"完整预检", mk("OPTIONS", map[string]string{
			"Origin": "http://oa.x:7013", "Access-Control-Request-Method": "POST"}), true},
		{"缺 ACRM 的裸 OPTIONS", mk("OPTIONS", map[string]string{
			"Origin": "http://oa.x:7013"}), false},
		{"缺 Origin", mk("OPTIONS", map[string]string{
			"Access-Control-Request-Method": "POST"}), false},
		{"GET 不是预检", mk("GET", map[string]string{
			"Origin": "http://oa.x:7013", "Access-Control-Request-Method": "POST"}), false},
	}
	for _, c := range cases {
		if got := IsPreflight(c.req); got != c.want {
			t.Errorf("%s: IsPreflight = %v，期望 %v", c.name, got, c.want)
		}
	}
}

// TestSanitizeHeaderValue 回显的是客户端完全可控的值，必须去控制字符并截断。
func TestSanitizeHeaderValue(t *testing.T) {
	if got := SanitizeHeaderValue("content-type\r\nX-Evil: 1"); strings.ContainsAny(got, "\r\n") {
		t.Fatalf("CR/LF 未被清除：%q", got)
	}
	if got := SanitizeHeaderValue(strings.Repeat("a", corsMaxHeaderLen*2)); len(got) > corsMaxHeaderLen {
		t.Fatalf("超长值未截断，len=%d", len(got))
	}
	if got := SanitizeHeaderValue("  x-token , content-type "); got != "x-token , content-type" {
		t.Fatalf("正常值不该被改动，got=%q", got)
	}
}

// TestWriteCORSHeaders 未认证响应补头：ACAO 必须是具体值，且带 Credentials 与 Vary。
func TestWriteCORSHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	w.Header().Add("Vary", "Accept-Encoding") // 已有的 Vary 不能被覆盖
	WriteCORSHeaders(w, "http://oa.x:7013")

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "http://oa.x:7013" {
		t.Fatalf("ACAO=%q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("ACAC=%q", got)
	}
	vary := w.Header().Values("Vary")
	if len(vary) != 2 || vary[0] != "Accept-Encoding" || vary[1] != "Origin" {
		t.Fatalf("Vary 应追加而不是覆盖，got=%v", vary)
	}
}

// TestWritePreflightHeaders 未指定 Allow-Headers 时回显请求的 ACRH，并封顶 Max-Age。
func TestWritePreflightHeaders(t *testing.T) {
	r := httptest.NewRequest("OPTIONS", "http://oa.x:7014/api", nil)
	r.Header.Set("Origin", "http://oa.x:7013")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "content-type, x-token")

	w := httptest.NewRecorder()
	WritePreflightHeaders(w, r, "http://oa.x:7013", CORSPolicy{MaxAge: 999999})

	if got := w.Header().Get("Access-Control-Allow-Headers"); got != "content-type, x-token" {
		t.Fatalf("ACAH 应回显请求头清单，got=%q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Methods"); got != corsDefaultMethods {
		t.Fatalf("ACAM 应回落默认值，got=%q", got)
	}
	if got := w.Header().Get("Access-Control-Max-Age"); got != "7200" {
		t.Fatalf("Max-Age 应被封顶到 7200，got=%q", got)
	}

	// 显式配置时不回显
	w2 := httptest.NewRecorder()
	WritePreflightHeaders(w2, r, "http://oa.x:7013", CORSPolicy{AllowHeaders: "x-only"})
	if got := w2.Header().Get("Access-Control-Allow-Headers"); got != "x-only" {
		t.Fatalf("显式配置应优先，got=%q", got)
	}
}

// TestResolveCORSPolicy 站点级按字段覆盖全局，没填的字段继续用全局。
func TestResolveCORSPolicy(t *testing.T) {
	g := CORSPolicy{
		AllowOrigins: BuildAllowOrigins("https://global.x"),
		AllowMethods: "GET",
		MaxAge:       100,
	}
	p := ResolveCORSPolicy("http://oa.x:7013", "", "", 0, g)
	if len(p.AllowOrigins) != 1 || p.AllowOrigins[0] != "http://oa.x:7013" {
		t.Fatalf("站点级 Origin 应覆盖全局，got=%v", p.AllowOrigins)
	}
	if p.AllowMethods != "GET" || p.MaxAge != 100 {
		t.Fatalf("站点没填的字段应沿用全局，got=%+v", p)
	}
	if !p.Enabled() {
		t.Fatal("有 Origin 就该是启用状态")
	}
	if ResolveCORSPolicy("", "", "", 0, CORSPolicy{}).Enabled() {
		t.Fatal("两级都没配时必须是关闭状态（默认关，存量零影响）")
	}
}

// TestResolveCORSPolicySiteOverride 站点级覆盖的三种语义。
//
// 关键是「-」哨兵：没有它的话，为某一个站点配的 Origin 会在所有继承全局的站点上
// 一并生效，而站点侧没有任何办法关掉——等于一处配置放宽了全部站点。
func TestResolveCORSPolicySiteOverride(t *testing.T) {
	g := CORSPolicy{AllowOrigins: BuildAllowOrigins("https://global.x"), AllowMethods: "GET"}

	if p := ResolveCORSPolicy("", "", "", 0, g); len(p.AllowOrigins) != 1 {
		t.Fatal("站点留空应沿用全局")
	}
	if p := ResolveCORSPolicy("-", "", "", 0, g); p.Enabled() {
		t.Fatal("站点填 - 应显式关闭，不得继承全局清单")
	}
	if p := ResolveCORSPolicy(" - ", "", "", 0, g); p.Enabled() {
		t.Fatal("哨兵两侧的空白应被忽略")
	}
	// 站点填了但全是非法值：以站点为准（空清单），不回落全局。
	// 回落等于用户想收紧、系统却悄悄放宽。
	if p := ResolveCORSPolicy("not-an-origin\n*", "", "", 0, g); p.Enabled() {
		t.Fatal("站点填了非法值应落到空清单，不得回落全局")
	}
	if p := ResolveCORSPolicy("http://site.x:8080", "", "", 0, g); len(p.AllowOrigins) != 1 ||
		p.AllowOrigins[0] != "http://site.x:8080" {
		t.Fatal("站点填了合法值应以站点为准")
	}
}

// TestAddVaryOrigin 命中与不命中都要带 Vary，缓存行为才对称。
func TestAddVaryOrigin(t *testing.T) {
	w := httptest.NewRecorder()
	AddVaryOrigin(w)
	if got := w.Header().Values("Vary"); len(got) != 1 || got[0] != "Origin" {
		t.Fatalf("Vary=%v", got)
	}
}
