package wafenginecore

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"SamWaf/model"
	"SamWaf/wafenginecore/accessgate"
)

// TestAccessTokenCookieNameFollowsScheme Cookie 名必须跟着 scheme 走。
//
// 这条和 accessgate.NormalizeHost 的单测是一对：那边验归一化本身，
// 这边验引擎真的把 r.TLS 传进去了。漏传的话所有 HTTPS 站点都会按
// HTTP 规则归一化，:443 不被去掉，Cookie 名与签发时对不上。
func TestAccessTokenCookieNameFollowsScheme(t *testing.T) {
	cfg := &accessgate.Config{CookiePrefix: "samwaf_ac"}

	plain := httptest.NewRequest("GET", "http://oa.x:443/", nil)
	plain.Host = "oa.x:443"

	secure := httptest.NewRequest("GET", "https://oa.x/", nil)
	secure.Host = "oa.x"
	secure.TLS = &tlsStateStub

	if accessTokenCookieName(cfg, plain) == accessTokenCookieName(cfg, secure) {
		t.Fatal("HTTP 的 oa.x:443 与 HTTPS 的 oa.x 派生出了同一个 Cookie 名，令牌会跨站点互通")
	}

	// 同主机名不同端口必须分开——这正是「已登录却一直 401」的根因
	a := httptest.NewRequest("GET", "http://oa.x:7013/", nil)
	a.Host = "oa.x:7013"
	b := httptest.NewRequest("GET", "http://oa.x:7014/", nil)
	b.Host = "oa.x:7014"
	if accessTokenCookieName(cfg, a) == accessTokenCookieName(cfg, b) {
		t.Fatal(":7013 与 :7014 派生出了同一个 Cookie 名，仍会互相覆盖")
	}
}

// TestStripAccessCookiesHandlesDerivedName 分站命名后，剥离逻辑必须照样把它摘掉。
//
// stripAccessCookies 按 CookiePrefix 前缀匹配，新名字仍以该前缀开头所以无需改动——
// 本用例就是把这个「无需改动」钉死，免得日后有人改了命名规则却忘了这里：
// 漏剥的后果是会话令牌明文进后端 access log 和我们自己的 web_logs。
func TestStripAccessCookiesHandlesDerivedName(t *testing.T) {
	cfg := &accessgate.Config{CookiePrefix: "samwaf_ac"}
	name := accessgate.TokenCookieName(cfg.CookiePrefix, "oa.x:7013")

	r := httptest.NewRequest("GET", "http://oa.x:7013/", nil)
	r.Header.Set("Cookie", "biz=1; "+name+"=secret; samwaf_ac_sso=alsosecret; other=2")

	if !stripAccessCookies(r, cfg) {
		t.Fatal("应当剥掉了东西")
	}
	got := r.Header.Get("Cookie")
	if got != "biz=1; other=2" {
		t.Fatalf("剥离结果不对：%q", got)
	}
}

// TestHostAccessConfigCORSRoundTrip 站点级 CORS 字段必须能从 access_json 里解析出来。
//
// AccessJSON 是一整串不透明 JSON 从前端透传到引擎的，json tag 写错不会报任何错，
// 只会表现为「前端填了、后端永远读不到」——这一类 bug 光靠编译和人眼看不出来。
func TestHostAccessConfigCORSRoundTrip(t *testing.T) {
	raw := `{"mode":1,"cors_allow_origins":"http://oa.x:7013\nhttps://app.oa.x",` +
		`"cors_allow_methods":"GET,POST","cors_allow_headers":"x-token","cors_max_age":300}`

	c := model.ParseAccessConfig(raw)
	if c.CorsAllowMethods != "GET,POST" || c.CorsAllowHeaders != "x-token" || c.CorsMaxAge != 300 {
		t.Fatalf("站点级 CORS 字段解析不出来：%+v", c)
	}

	cfg := &accessgate.Config{}
	p := accessCORSPolicy(cfg, c)
	if len(p.AllowOrigins) != 2 {
		t.Fatalf("Origin 清单应解析出 2 条，got=%v", p.AllowOrigins)
	}
	if _, ok := accessgate.MatchOrigin("http://oa.x:7013", p.AllowOrigins); !ok {
		t.Fatal("白名单里的 Origin 应命中")
	}
	if _, ok := accessgate.MatchOrigin("http://oa.x:7013.evil.com", p.AllowOrigins); ok {
		t.Fatal("后缀拼接的 Origin 绝不能命中")
	}

	// 越界的 max_age 归零 = 沿用全局；控制字符必须在解析阶段消掉
	bad := model.ParseAccessConfig(`{"cors_max_age":99999,"cors_allow_methods":"GET\r\nX-Evil: 1"}`)
	if bad.CorsMaxAge != 0 {
		t.Fatalf("越界 max_age 应归零，got=%d", bad.CorsMaxAge)
	}
	for _, ch := range []byte{'\r', '\n'} {
		for i := 0; i < len(bad.CorsAllowMethods); i++ {
			if bad.CorsAllowMethods[i] == ch {
				t.Fatalf("methods 里残留控制字符：%q", bad.CorsAllowMethods)
			}
		}
	}

	// 空配置必须落在「未启用」，存量站点行为零变化
	if accessCORSPolicy(&accessgate.Config{}, model.ParseAccessConfig("")).Enabled() {
		t.Fatal("两级都没配时必须是关闭状态")
	}
}

// TestHostAccessConfigCORSMarshalable 站点配置要能原样存回去，
// 否则管理端编辑一次就会把 CORS 设置抹掉。
func TestHostAccessConfigCORSMarshalable(t *testing.T) {
	c := model.HostAccessConfig{Mode: 1, CorsAllowOrigins: "http://oa.x:7013", CorsMaxAge: 300}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	back := model.ParseAccessConfig(string(b))
	if back.CorsAllowOrigins != c.CorsAllowOrigins || back.CorsMaxAge != c.CorsMaxAge {
		t.Fatalf("往返丢字段：%+v", back)
	}
}

// TestAccessUnauthorizedJSONHasNoCORSByDefault 没配白名单时不得回显任何 CORS 头。
//
// 默认关是硬约束：存量用户升级后，未认证响应必须和现在一模一样。
func TestAccessUnauthorizedJSONHasNoCORSByDefault(t *testing.T) {
	w := httptest.NewRecorder()
	writeAccessUnauthorizedJSON(w, "http://sso.x/samwaf_access/login")

	for _, h := range []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Credentials",
		"Access-Control-Allow-Methods",
	} {
		if v := w.Header().Get(h); v != "" {
			t.Fatalf("未配白名单时不该出现 %s=%q", h, v)
		}
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("状态码=%d", w.Code)
	}
}

// tlsStateStub 只用来把 r.TLS 置为非 nil，内容无关紧要。
var tlsStateStub tls.ConnectionState
