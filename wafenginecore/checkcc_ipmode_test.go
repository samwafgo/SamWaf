package wafenginecore

import (
	"net/http/httptest"
	"testing"

	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/ccrule"
)

func ipModeRule(t *testing.T, id string) *ccrule.CompiledRule {
	t.Helper()
	rule := &model.AntiCCRule{
		RuleName:   "ipmode",
		IsEnable:   1,
		MatchMode:  model.CCMatchModeAll,
		CountScope: model.CCCountScopeAll,
		StatDim:    model.CCStatDimIP,
		WindowSec:  60,
		Threshold:  1000000, // 只看计数落在哪个 IP 上，不触发动作
		Action:     model.CCActionObserve,
	}
	rule.Id = id
	cr, err := ccrule.Compile(rule)
	if err != nil {
		t.Fatalf("编译规则失败: %v", err)
	}
	return cr
}

// 全局 CC 规则取客户端 IP 必须按【被访问站点】的 IPMode，而不是全局网站自己的。
//
// IPMode 描述的是该站点部署在什么后面（是否有前置代理/CDN），属于部署事实；
// 全局网站不承载流量，它的这个值取不到实际意义。两者不一致时（实测存在：
// 全局网站 nic、业务站点 proxy），同一个请求会在站点规则与全局规则里按两个不同的 IP 计数；
// 站点在 CDN 后面时，全局规则会把所有访客并到少数回源 IP 上。
func TestCheckCCByRules_GlobalRuleUsesVisitedHostIPMode(t *testing.T) {
	waf := &WafEngine{}
	GCCCounter.Reset()

	site := &wafenginmodel.HostSafe{}
	site.Host.Code = "sitecode"
	site.Host.IPMode = "proxy" // 站点在代理后面，真实客户端 IP 走 SRC_IP
	site.Host.GUARD_STATUS = 1

	globalHost := &wafenginmodel.HostSafe{}
	globalHost.Host.Code = "globalcode"
	globalHost.Host.IPMode = "nic" // 全局网站是默认的网卡模式
	globalHost.Host.GUARD_STATUS = 1
	rule := ipModeRule(t, "rule-global")
	globalHost.CCRules = []*ccrule.CompiledRule{rule}

	log := &innerbean.WebLog{NetSrcIp: "10.0.0.1", SRC_IP: "1.2.3.4"}
	waf.checkCCByRules(httptest.NewRequest("GET", "/", nil), log, site, globalHost)

	// 再各记一次：引擎已经记过的那个 IP 会返回 2，没记过的返回 1
	if got := GCCCounter.Incr(rule.Rule.Id, "1.2.3.4", 60).Count; got != 2 {
		t.Fatalf("全局规则应按被访问站点的 proxy 口径记在 1.2.3.4 上，实际该键计数为 %d", got)
	}
	if got := GCCCounter.Incr(rule.Rule.Id, "10.0.0.1", 60).Count; got != 1 {
		t.Fatalf("不应按全局网站的 nic 口径记在连接IP 10.0.0.1 上，实际该键计数为 %d", got)
	}
}

// 站点自己的规则口径不变（这条是上面改动的对照组，防止改歪）
func TestCheckCCByRules_SiteRuleUsesOwnIPMode(t *testing.T) {
	waf := &WafEngine{}
	GCCCounter.Reset()

	site := &wafenginmodel.HostSafe{}
	site.Host.Code = "sitecode"
	site.Host.IPMode = "proxy"
	site.Host.GUARD_STATUS = 1
	rule := ipModeRule(t, "rule-site")
	site.CCRules = []*ccrule.CompiledRule{rule}

	log := &innerbean.WebLog{NetSrcIp: "10.0.0.1", SRC_IP: "1.2.3.4"}
	waf.checkCCByRules(httptest.NewRequest("GET", "/", nil), log, site, nil)

	if got := GCCCounter.Incr(rule.Rule.Id, "1.2.3.4", 60).Count; got != 2 {
		t.Fatalf("站点规则应按本站点的 proxy 口径记在 1.2.3.4 上，实际该键计数为 %d", got)
	}
}
