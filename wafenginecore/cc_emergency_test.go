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
	"SamWaf/model/wafenginmodel"
)

func newEmergencyHost(code string, mode int, until int64) *wafenginmodel.HostSafe {
	h := &wafenginmodel.HostSafe{}
	h.Host.Code = code
	h.Host.EmergencyMode = mode
	h.Host.EmergencyUntil = until
	return h
}

// 到期判定在读取侧完成：库里写着「开」但已过自动关闭时间时，必须当成关。
// 靠定时任务改库的话，任务没跑到的那段时间里库与实际行为不一致，比晚关几秒更难查。
func TestIsEmergencyActive(t *testing.T) {
	now := time.Now().Unix()
	cases := []struct {
		name  string
		mode  int
		until int64
		want  bool
	}{
		{"未开启", 0, 0, false},
		{"开启且不自动关", 1, 0, true},
		{"开启且未到期", 1, now + 600, true},
		{"开启但已过期", 1, now - 1, false},
		{"关闭但留着到期时间", 0, now + 600, false},
	}
	for _, c := range cases {
		h := &model.Hosts{EmergencyMode: c.mode, EmergencyUntil: c.until}
		if got := h.IsEmergencyActive(now); got != c.want {
			t.Fatalf("%s: 期望 %v，实际 %v", c.name, c.want, got)
		}
	}
}

// 全局网站开了紧急模式，所有站点都算开。
// 被打的时候逐个站点去点开关，正是最不该在这时候做的事。
func TestIsEmergencyOn_GlobalCoversAllSites(t *testing.T) {
	waf := &WafEngine{}
	site := newEmergencyHost("site", 0, 0)
	globalOn := newEmergencyHost("global", 1, 0)
	globalOff := newEmergencyHost("global", 0, 0)

	if !waf.isEmergencyOn(site, globalOn) {
		t.Fatalf("全局网站开启紧急模式时，普通站点也应生效")
	}
	if waf.isEmergencyOn(site, globalOff) {
		t.Fatalf("两边都没开时不应进入紧急模式")
	}
	if !waf.isEmergencyOn(newEmergencyHost("site", 1, 0), globalOff) {
		t.Fatalf("站点自己开启时应生效")
	}
	if waf.isEmergencyOn(site, nil) {
		t.Fatalf("取不到全局网站时不应误判为开启")
	}
}

// 紧急模式必须复用 CC 人机验证那套标记，闸门才认得；
// 并且和 CC 规则动作一样，通过之后要能进免挑战期，不能每个请求都重新挑战。
func TestApplyEmergencyCaptcha_Lifecycle(t *testing.T) {
	old := global.GCACHE_WAFCACHE
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	defer func() { global.GCACHE_WAFCACHE = old }()

	waf := &WafEngine{}
	host := newEmergencyHost("hostcode", 1, 0)
	ip := "1.2.3.4"

	// ① 首次访问：留下「需验证」标记，闸门据此发起挑战
	log1 := &innerbean.WebLog{SRC_IP: ip}
	waf.applyEmergencyCaptcha(httptest.NewRequest("GET", "/", nil), log1, host)
	if !IsCCCaptchaRequired(host.Host.Code, ip) {
		t.Fatalf("紧急模式下首次访问应要求人机验证")
	}
	if log1.RULE != "CC紧急模式" {
		t.Fatalf("日志应写明是紧急模式要求的验证，实际=%q", log1.RULE)
	}

	// ② 访客完成挑战，拿到凭证后再来
	token := "tok-emg"
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_CAPTCHA_PASS+token+ip, "ok", time.Hour)
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(&http.Cookie{Name: "samwaf_captcha_token", Value: token})
	log2 := &innerbean.WebLog{SRC_IP: ip}
	waf.applyEmergencyCaptcha(req2, log2, host)

	if !isCCCaptchaInGrace(host.Host.Code, ip) {
		t.Fatalf("完成挑战后应进入免挑战期，否则每个请求都会被重新挑战")
	}
	if IsCCCaptchaRequired(host.Host.Code, ip) {
		t.Fatalf("进入免挑战期后不应仍要求验证")
	}

	// ③ 免挑战期内再来：不再挑战，且日志能看出是被放行的
	log3 := &innerbean.WebLog{SRC_IP: ip}
	waf.applyEmergencyCaptcha(httptest.NewRequest("GET", "/", nil), log3, host)
	if IsCCCaptchaRequired(host.Host.Code, ip) {
		t.Fatalf("免挑战期内不应重复要求验证")
	}
	if log3.RULE != "CC紧急模式-免挑战期内放行" {
		t.Fatalf("免挑战期放行的文案要与要求验证区分开，实际=%q", log3.RULE)
	}
}

// 紧急模式要求验证时，必须作废访客手里的陈旧凭证。
// 否则常开验证码留下的 24 小时凭证会让紧急模式对老访客整个失效。
func TestApplyEmergencyCaptcha_RevokesStalePass(t *testing.T) {
	old := global.GCACHE_WAFCACHE
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	defer func() { global.GCACHE_WAFCACHE = old }()

	host := newEmergencyHost("hostcode", 1, 0)
	ip := "1.2.3.4"
	token := "tok-stale"
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_CAPTCHA_PASS+token+ip, "ok", 24*time.Hour)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "samwaf_captcha_token", Value: token})
	(&WafEngine{}).applyEmergencyCaptcha(req, &innerbean.WebLog{SRC_IP: ip}, host)

	if global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_CAPTCHA_PASS + token + ip) {
		t.Fatalf("紧急模式要求验证时应作废陈旧凭证")
	}
}
