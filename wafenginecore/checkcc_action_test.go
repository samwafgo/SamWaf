package wafenginecore

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"SamWaf/cache"
	"SamWaf/enums"
	"SamWaf/global"

	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/ccrule"
)

func newActionRule(action string) *ccrule.CompiledRule {
	return &ccrule.CompiledRule{
		Rule: &model.AntiCCRule{
			RuleName:      "t",
			Action:        action,
			ActionSeconds: 300,
			BanScope:      model.CCBanScopeHost,
		},
	}
}

func newActionHost() *wafenginmodel.HostSafe {
	h := &wafenginmodel.HostSafe{}
	h.Host.Code = "hostcode"
	return h
}

// 人机验证动作不能自己返回拦截：挑战由检测链后面的验证码闸门发起，
// 在这里拦下会让挑战页发不出去，已通过验证的访客再次超阈值时也会被判成普通拦截。
func TestApplyCCAction_CaptchaDoesNotBlock(t *testing.T) {
	waf := &WafEngine{}
	log := &innerbean.WebLog{SRC_IP: "1.2.3.4"}

	res, stop := waf.applyCCAction(httptest.NewRequest("GET", "/", nil), newActionRule(model.CCActionCaptcha), log, newActionHost(), "1.2.3.4", "hostcode")
	if res.IsBlock {
		t.Fatalf("人机验证动作不应返回拦截结果，否则请求到不了验证码闸门")
	}
	if !stop {
		t.Fatalf("人机验证动作应结束本轮CC规则匹配")
	}
}

// 其余三个动作的阻断/放行语义不能被上面的改动带偏
func TestApplyCCAction_OtherActions(t *testing.T) {
	waf := &WafEngine{}
	cases := []struct {
		action  string
		isBlock bool
		stop    bool
	}{
		{model.CCActionObserve, false, false},
		{model.CCActionDeny, true, true},
		{model.CCActionBan, true, true},
	}
	for _, c := range cases {
		log := &innerbean.WebLog{SRC_IP: "1.2.3.4"}
		res, stop := waf.applyCCAction(httptest.NewRequest("GET", "/", nil), newActionRule(c.action), log, newActionHost(), "1.2.3.4", "hostcode")
		if res.IsBlock != c.isBlock || stop != c.stop {
			t.Fatalf("动作 %s: 期望 block=%v stop=%v，实际 block=%v stop=%v",
				c.action, c.isBlock, c.stop, res.IsBlock, stop)
		}
	}
}

// 人机验证必须是可重复的关卡：通过一次之后只在免挑战期内不再挑战，
// 期满再超阈值要重新验证。若沿用站点级通行凭证（默认 24 小时），
// 这个动作就退化成一次性关卡。
func TestApplyCCAction_CaptchaIsRepeatable(t *testing.T) {
	old := global.GCACHE_WAFCACHE
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	defer func() { global.GCACHE_WAFCACHE = old }()

	waf := &WafEngine{}
	host := newActionHost()
	rule := newActionRule(model.CCActionCaptcha)
	ip := "1.2.3.4"
	req := httptest.NewRequest("GET", "/", nil)

	// 第一次超阈值：留下"需验证"标记
	waf.applyCCAction(req, rule, &innerbean.WebLog{SRC_IP: ip}, host, ip, "hostcode")
	if !IsCCCaptchaRequired(host.Host.Code, ip) {
		t.Fatalf("第一次超阈值应标记为需要人机验证")
	}

	// 通过验证：标记换成免挑战期
	GrantCCCaptchaGrace(host.Host.Code, ip)
	if IsCCCaptchaRequired(host.Host.Code, ip) {
		t.Fatalf("通过验证后不应仍处于需验证状态")
	}
	if !isCCCaptchaInGrace(host.Host.Code, ip) {
		t.Fatalf("通过验证后应进入免挑战期")
	}

	// 免挑战期内再超阈值：不重复挑战
	waf.applyCCAction(req, rule, &innerbean.WebLog{SRC_IP: ip}, host, ip, "hostcode")
	if IsCCCaptchaRequired(host.Host.Code, ip) {
		t.Fatalf("免挑战期内不应重复要求验证")
	}

	// 免挑战期结束后再超阈值：重新要求验证
	global.GCACHE_WAFCACHE.Remove(ccCaptchaGraceKey(host.Host.Code, ip))
	waf.applyCCAction(req, rule, &innerbean.WebLog{SRC_IP: ip}, host, ip, "hostcode")
	if !IsCCCaptchaRequired(host.Host.Code, ip) {
		t.Fatalf("免挑战期结束后再超阈值应重新要求验证，否则动作退化成一次性关卡")
	}
}

// 超阈值时必须作废客户端手里的通行凭证，否则站点级凭证有效期内怎么超量都不会被挑战
func TestApplyCCAction_CaptchaRevokesStalePass(t *testing.T) {
	old := global.GCACHE_WAFCACHE
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	defer func() { global.GCACHE_WAFCACHE = old }()

	ip := "1.2.3.4"
	token := "tok-abc"
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_CAPTCHA_PASS+token+ip, "ok", 24*time.Hour)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "samwaf_captcha_token", Value: token})

	(&WafEngine{}).applyCCAction(req, newActionRule(model.CCActionCaptcha),
		&innerbean.WebLog{SRC_IP: ip}, newActionHost(), ip, "hostcode")

	if global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_CAPTCHA_PASS + token + ip) {
		t.Fatalf("超阈值后旧的通行凭证应被作废")
	}
}

// 免挑战期内放行与本次要求验证，日志文案必须能分开。
// 两条路径都不阻断请求，文案一样的话，看到「人机验证」却没弹挑战只能理解成功能坏了。
func TestApplyCCAction_GraceIsDistinguishableInLog(t *testing.T) {
	old := global.GCACHE_WAFCACHE
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	defer func() { global.GCACHE_WAFCACHE = old }()

	waf := &WafEngine{}
	host := newActionHost()
	rule := newActionRule(model.CCActionCaptcha)
	ip := "1.2.3.4"
	req := httptest.NewRequest("GET", "/", nil)

	// 第一次：要求验证
	first := &innerbean.WebLog{SRC_IP: ip}
	waf.applyCCAction(req, rule, first, host, ip, "hostcode")
	if !strings.HasPrefix(first.RULE, "CC人机验证:") {
		t.Fatalf("要求验证时的日志文案不对：%q", first.RULE)
	}

	// 通过验证后进入免挑战期，再次超阈值
	GrantCCCaptchaGrace(host.Host.Code, ip)
	second := &innerbean.WebLog{SRC_IP: ip}
	waf.applyCCAction(req, rule, second, host, ip, "hostcode")

	if second.RULE == first.RULE {
		t.Fatalf("免挑战期内放行与要求验证的日志文案相同(%q)，用户无法分辨为什么没弹挑战", second.RULE)
	}
	if !strings.Contains(second.RULE, "免挑战期") {
		t.Fatalf("免挑战期内放行的日志应写明原因，实际：%q", second.RULE)
	}
	// 免挑战期内不应再写「需验证」标记，否则闸门会凭空发起挑战
	if IsCCCaptchaRequired(host.Host.Code, ip) {
		t.Fatalf("免挑战期内不应重新标记需要验证")
	}
}

// 触发来源要能被闸门取到，否则日志里只有「显示图形验证码」，查不出是谁要求的。
// 「需验证」键的取值格式必须保持不变——来源另存一个键，
// 否则升级瞬间由旧版本写下、尚未过期的标记会失效，正在验证中的客户端被重复挑战。
func TestRequireCaptcha_SourceAndKeyCompat(t *testing.T) {
	old := global.GCACHE_WAFCACHE
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	defer func() { global.GCACHE_WAFCACHE = old }()

	host, ip := "hostcode", "1.2.3.4"
	RequireCaptcha(host, ip, 60, "CC规则 测试[CC-ABC123]")

	if !IsCCCaptchaRequired(host, ip) {
		t.Fatalf("应处于需验证状态")
	}
	// 取值仍是秒数（int），GrantCCCaptchaGrace 依赖它换算免挑战期
	if v, err := global.GCACHE_WAFCACHE.GetInt(ccCaptchaRequiredKey(host, ip)); err != nil || v != 60 {
		t.Fatalf("「需验证」键的取值格式变了：v=%d err=%v", v, err)
	}
	if got := CaptchaRequireSource(host, ip); got != "CC规则 测试[CC-ABC123]" {
		t.Fatalf("取不到触发来源，实际 %q", got)
	}

	// 通过验证后来源要一并清掉，不能留到下一轮张冠李戴
	GrantCCCaptchaGrace(host, ip)
	if got := CaptchaRequireSource(host, ip); got != "" {
		t.Fatalf("通过验证后来源应被清除，实际 %q", got)
	}
}

// 没有来源时不应报错，也不应把空串写进缓存（旧标记 / 其它来源未传 source 的情况）
func TestRequireCaptcha_NoSource(t *testing.T) {
	old := global.GCACHE_WAFCACHE
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	defer func() { global.GCACHE_WAFCACHE = old }()

	RequireCaptcha("h", "2.3.4.5", 30, "")
	if !IsCCCaptchaRequired("h", "2.3.4.5") {
		t.Fatalf("没有来源也应正常标记需验证")
	}
	if got := CaptchaRequireSource("h", "2.3.4.5"); got != "" {
		t.Fatalf("未传来源时应返回空串，实际 %q", got)
	}
}
