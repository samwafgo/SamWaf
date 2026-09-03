package wafenginecore

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"SamWaf/cache"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
)

// 模拟验证码闸门在检测链后半段做的那一步。
// CC 检测（applyCCAction）跑在它前面，两者之间的交接必须成立，
// 否则免挑战期永远发不出来。
func gateStep(t *testing.T, r *http.Request, hostCode, ip string) {
	t.Helper()
	if IsCCCaptchaRequired(hostCode, ip) && hasCaptchaPass(r, ip) {
		GrantCCCaptchaGrace(hostCode, ip)
	}
}

// 访客完成挑战后，必须真的能拿到免挑战期。
//
// 这一条守的是两个检测点之间的时序：闸门是靠「访客带着有效凭证出现」才发放免挑战期的，
// 而 CC 检测跑在闸门之前。CC 这一步若无条件作废凭证，闸门就永远看不到有效凭证，
// 访客每个请求都会被重新挑战，直到计数窗口自己漏空为止——
// 表现是「验证码怎么点都点不完」。
func TestApplyCCAction_GraceReachableAfterVisitorPassed(t *testing.T) {
	old := global.GCACHE_WAFCACHE
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	defer func() { global.GCACHE_WAFCACHE = old }()

	waf := &WafEngine{}
	host := newActionHost()
	rule := newActionRule(model.CCActionCaptcha)
	ip := "1.2.3.4"

	// ① 第一次超阈值：访客手上什么都没有，留下「需验证」标记
	req1 := httptest.NewRequest("GET", "/", nil)
	waf.applyCCAction(req1, rule, &innerbean.WebLog{SRC_IP: ip}, host, ip, "hostcode")
	gateStep(t, req1, host.Host.Code, ip)
	if !IsCCCaptchaRequired(host.Host.Code, ip) {
		t.Fatalf("第一次超阈值应标记为需要人机验证")
	}

	// ② 访客完成挑战，拿到通行凭证
	token := "tok-fresh"
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_CAPTCHA_PASS+token+ip, "ok", 24*time.Hour)

	// ③ 下一个请求：仍在计数窗口内，还是会超阈值，于是又走一遍 CC 检测再进闸门
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(&http.Cookie{Name: "samwaf_captcha_token", Value: token})
	waf.applyCCAction(req2, rule, &innerbean.WebLog{SRC_IP: ip}, host, ip, "hostcode")
	gateStep(t, req2, host.Host.Code, ip)

	if !isCCCaptchaInGrace(host.Host.Code, ip) {
		t.Fatalf("访客已完成挑战，应进入免挑战期；否则每个请求都会被重新挑战")
	}
	if IsCCCaptchaRequired(host.Host.Code, ip) {
		t.Fatalf("已进入免挑战期，不应仍处于需验证状态")
	}

	// ④ 免挑战期内再超阈值：不再挑战
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.AddCookie(&http.Cookie{Name: "samwaf_captcha_token", Value: token})
	waf.applyCCAction(req3, rule, &innerbean.WebLog{SRC_IP: ip}, host, ip, "hostcode")
	if IsCCCaptchaRequired(host.Host.Code, ip) {
		t.Fatalf("免挑战期内不应重复要求验证")
	}
}

// 上面那条修好之后，不能把「作废陈旧凭证」一起弄没了：
// 访客拿着很久以前站点常开验证码换来的凭证、此前并没有被要求过验证时，
// 超阈值仍然必须作废它并重新挑战，否则凭证有效期内怎么超量都不会被拦。
func TestApplyCCAction_StalePassStillRevokedWhenNotChallenged(t *testing.T) {
	old := global.GCACHE_WAFCACHE
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	defer func() { global.GCACHE_WAFCACHE = old }()

	host := newActionHost()
	ip := "1.2.3.4"
	token := "tok-stale"
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_CAPTCHA_PASS+token+ip, "ok", 24*time.Hour)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "samwaf_captcha_token", Value: token})

	// 没有任何「需验证」标记在先 —— 这张凭证不是本轮挑战换来的
	(&WafEngine{}).applyCCAction(req, newActionRule(model.CCActionCaptcha),
		&innerbean.WebLog{SRC_IP: ip}, host, ip, "hostcode")

	if global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_CAPTCHA_PASS + token + ip) {
		t.Fatalf("此前未要求过验证时，陈旧凭证应被作废")
	}
	if !IsCCCaptchaRequired(host.Host.Code, ip) {
		t.Fatalf("陈旧凭证被作废后应要求重新验证")
	}
	if isCCCaptchaInGrace(host.Host.Code, ip) {
		t.Fatalf("陈旧凭证不该被当成「本轮已通过」而直接进免挑战期")
	}
}
