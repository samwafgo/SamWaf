package wafenginecore

import (
	"SamWaf/cache"
	"SamWaf/cache/cachetest"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"testing"
	"time"
)

func TestCheckRuleBanWithoutSeparateSwitch(t *testing.T) {
	oldCache := global.GCACHE_WAFCACHE
	t.Cleanup(func() { global.GCACHE_WAFCACHE = oldCache })
	for name, store := range map[string]cache.CacheStore{
		"memory": cache.InitWafCache(),
		"json":   cachetest.NewJSONRoundTrip(),
	} {
		t.Run(name, func(t *testing.T) {
			global.GCACHE_WAFCACHE = store
			checkRuleBanWithoutSeparateSwitch(t)
		})
	}
}

func checkRuleBanWithoutSeparateSwitch(t *testing.T) {

	waf := newTestEngineWithGlobalRule(t, "")
	host := newTestSiteHost(t, `rule Rtest001 "ban" salience 10 {
		when MF.URL == "/ban-test"
		then RF.Ban(10);
	}`)
	host.Host.Code = "ban-site"
	log := &innerbean.WebLog{URL: "/ban-test", SRC_IP: "198.51.100.10", NetSrcIp: "198.51.100.10"}
	result := waf.CheckRule(nil, log, nil, host, nil)
	if !result.IsBlock {
		t.Fatal("Ban must block the matching request")
	}
	key := model.BuildRuleBanKey(host.Host.Code, log.SRC_IP)
	var minutes int64
	err := global.GCACHE_WAFCACHE.GetAs(key, &minutes)
	if err != nil || minutes != 10 {
		t.Fatalf("ban minutes = %d, err = %v", minutes, err)
	}
	expires, err := global.GCACHE_WAFCACHE.GetExpireTime(key)
	if err != nil || time.Until(expires) < 9*time.Minute || time.Until(expires) > 10*time.Minute {
		t.Fatalf("unexpected ban expiry: %v, err = %v", expires, err)
	}
	waf.CheckRule(nil, log, nil, host, nil)
	after, _ := global.GCACHE_WAFCACHE.GetExpireTime(key)
	if !expires.Equal(after) {
		t.Fatal("repeated matches must not renew the ban")
	}
	if hit, _ := matchRuleBan("other-site", log.NetSrcIp, log.SRC_IP, host.Host.IPMode); hit != "" {
		t.Fatal("ban must be scoped to the triggering host")
	}

	global.GCACHE_WAFCACHE.Remove(key)
	host.Host.LogOnlyMode = 1
	waf.CheckRule(nil, log, nil, host, nil)
	if global.GCACHE_WAFCACHE.IsKeyExist(key) {
		t.Fatal("log-only mode must not create bans")
	}
}

func TestRuleBanArbitrationPreservesMinutes(t *testing.T) {
	rh := buildRuleHelper(t, `
rule Rdeny "deny" salience 10 { when MF.URL == "/x" then RF.Deny(); }
rule Rban10 "ban10" salience 10 { when MF.URL == "/x" then RF.Ban(10); }
rule Rban30 "ban30" salience 10 { when MF.URL == "/x" then RF.Ban(30); }
`)
	matches, err := rh.Match("MF", &innerbean.WebLog{URL: "/x"})
	if err != nil || len(matches) != 3 {
		t.Fatalf("matches = %d, err = %v", len(matches), err)
	}
	info := pickRuleAction(rh, matches)
	if info.Action != utils.RuleActionBan || info.BanMinutes != 30 {
		t.Fatalf("unexpected action: %+v", info)
	}

	ban := ruleMatchResult{Matched: true, TopSalience: 10, Action: info}
	deny := ruleMatchResult{Matched: true, TopSalience: 10, Action: utils.RuleActionInfo{Action: utils.RuleActionDeny}}
	for _, result := range []ruleMatchResult{arbitrate(ban, deny), arbitrate(deny, ban), arbitrate(ban, ban)} {
		if result.Action.Action != utils.RuleActionBan || result.Action.BanMinutes != 30 {
			t.Fatalf("cross-scope arbitration lost ban duration: %+v", result)
		}
	}
}
