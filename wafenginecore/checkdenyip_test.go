package wafenginecore

// 引擎侧的 IP 黑名单用例（配合 issue #898）：
//   - TestCheckDenyIP_HostMoved_OldHostStopsBlocking 钉死 API 层修复所依赖的契约：
//     旧网站收到「空名单」通知后，确实不再拦截。这个用例修复前后都绿，不是 fail-before 证据。
//   - TestCheckDenyIP_GlobalHostMissing_ShouldNotPanic 是 nil 解引用的回归，修复前会 panic。

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafenginecore/ipset"
	"net/http"
	"testing"
)

// newDenyIPTestEngine 造一个只含路由快照的引擎；global 为 true 时登记全局网站（GUARD_STATUS=0，不参与判定）。
func newDenyIPTestEngine(t *testing.T, withGlobalHost bool) *WafEngine {
	t.Helper()
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "json")

	oldGlobalName := global.GWAF_GLOBAL_HOST_NAME
	global.GWAF_GLOBAL_HOST_NAME = "全局网站:0"
	t.Cleanup(func() { global.GWAF_GLOBAL_HOST_NAME = oldGlobalName })

	waf := &WafEngine{}
	waf.InitRouting()
	waf.withWriteTable(func(nt *routingTable) {
		if withGlobalHost {
			nt.HostTarget[global.GWAF_GLOBAL_HOST_NAME] = &wafenginmodel.HostSafe{
				Host: model.Hosts{GUARD_STATUS: 0}, // 全局网站不参与本用例判定
			}
		}
		nt.HostTarget["a.com:80"] = &wafenginmodel.HostSafe{
			Host:         model.Hosts{Code: "codeA", GUARD_STATUS: 1},
			IPBlockLists: []model.IPBlockList{{Ip: "1.2.3.4"}},
		}
		nt.HostCode["codeA"] = "a.com:80"
		nt.HostTarget["b.com:80"] = &wafenginmodel.HostSafe{
			Host:         model.Hosts{Code: "codeB", GUARD_STATUS: 1},
			IPBlockLists: []model.IPBlockList{},
		}
		nt.HostCode["codeB"] = "b.com:80"
	})
	return waf
}

// isBlocked 按 hostCode 从当前快照重新取 HostSafe 再判定。
// 必须每次重新取：UpdateHost 是 copy-on-write，更新前捕获的指针永远指向旧快照。
func isBlocked(t *testing.T, waf *WafEngine, hostCode, clientIP string) bool {
	t.Helper()
	h, ok := waf.GetHostByCode(hostCode)
	if !ok {
		t.Fatalf("快照里找不到 hostCode=%s", hostCode)
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+h.Host.Host+"/", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	weblog := &innerbean.WebLog{NetSrcIp: clientIP, SRC_IP: clientIP}
	return waf.CheckDenyIP(req, weblog, nil, h, waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]).IsBlock
}

// TestCheckDenyIP_HostMoved_OldHostStopsBlocking 规则从网站 A 移到 B 后，A 必须停止拦截、B 开始拦截。
func TestCheckDenyIP_HostMoved_OldHostStopsBlocking(t *testing.T) {
	waf := newDenyIPTestEngine(t, true)

	// 1) 初始：A 拦截，B 放行
	if !isBlocked(t, waf, "codeA", "1.2.3.4") {
		t.Fatalf("初始状态下网站 A 应该拦截 1.2.3.4")
	}
	if isBlocked(t, waf, "codeB", "1.2.3.4") {
		t.Fatalf("初始状态下网站 B 不应拦截 1.2.3.4")
	}

	// 2) 模拟 main.go 收到两条 ChanTypeBlockIP 通知后的动作（规则从 A 移到 B）
	waf.UpdateHost("codeA", func(h *wafenginmodel.HostSafe) { h.IPBlockLists = []model.IPBlockList{} })
	waf.UpdateHost("codeB", func(h *wafenginmodel.HostSafe) {
		h.IPBlockLists = []model.IPBlockList{{Ip: "1.2.3.4"}}
	})

	// 3) 旧网站不再拦截（issue #898 的表象），新网站开始拦截
	if isBlocked(t, waf, "codeA", "1.2.3.4") {
		t.Errorf("规则已移走，网站 A 不应再拦截 1.2.3.4（旧网站内存名单没刷新）")
	}
	if !isBlocked(t, waf, "codeB", "1.2.3.4") {
		t.Errorf("规则已移入，网站 B 应该拦截 1.2.3.4")
	}
}

// TestCheckDenyIP_GlobalHostMissing_ShouldNotPanic 路由快照里没有全局网站时不能 panic。
// 修复前 checkdenyip.go 直接解引用 HostTarget["全局网站:0"]，缺 key 即 nil 解引用崩溃。
func TestCheckDenyIP_GlobalHostMissing_ShouldNotPanic(t *testing.T) {
	waf := newDenyIPTestEngine(t, false)

	if _, ok := waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]; ok {
		t.Fatalf("用例前置条件要求快照里没有全局网站")
	}

	// 局部名单命中：即使全局网站缺失也要正常返回拦截
	if !isBlocked(t, waf, "codeA", "1.2.3.4") {
		t.Errorf("局部名单命中时应拦截")
	}
	// 局部名单不命中：走到全局分支，必须安全跳过而不是 panic
	if isBlocked(t, waf, "codeA", "9.9.9.9") {
		t.Errorf("没有任何名单命中时不应拦截")
	}
}

// TestCheckDenyIP_ThreatIPIncludesChannelName 验证威胁情报拦截在 Title 中标明来源渠道，
// 仅 system 层渠道不误入 WAF 拦截，且 inferAttackType 对含敏感关键词的渠道名不误判攻击类型。
func TestCheckDenyIP_ThreatIPIncludesChannelName(t *testing.T) {
	waf := newDenyIPTestEngine(t, true)
	oldIdx := ipset.GetGlobalThreatIndex()
	t.Cleanup(func() { ipset.SetGlobalThreatIndex(oldIdx) })

	ipset.SetGlobalThreatIndex(&ipset.ThreatIndex{
		WAFUnion: ipset.BuildMatchSet([]string{"203.0.113.5", "192.0.2.8"}),
		Channels: []ipset.ThreatChannelMatcher{
			{Code: "a_sys", Name: "System Only", LandTarget: "system", Set: ipset.BuildMatchSet([]string{"198.51.100.7"})},
			{Code: "firehol", Name: "FireHOL Level1", LandTarget: "both", Set: ipset.BuildMatchSet([]string{"203.0.113.5"})},
			{Code: "ipsum", Name: "SQL Bot Scanner", LandTarget: "waf", Set: ipset.BuildMatchSet([]string{"203.0.113.5", "192.0.2.8"})},
		},
	})

	h, _ := waf.GetHostByCode("codeB")
	req, _ := http.NewRequest(http.MethodGet, "http://b.com/", nil)

	// 1. 仅 system 渠道的 IP 不能在 WAF 层被拦截
	resSys := waf.CheckDenyIP(req, &innerbean.WebLog{NetSrcIp: "198.51.100.7", SRC_IP: "198.51.100.7"}, nil, h, waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME])
	if resSys.IsBlock {
		t.Fatalf("仅 system 渠道 IP 不应在 WAF 层拦截，实际 %+v", resSys)
	}

	// 2. 多渠道同时命中：按稳定顺序取首命中渠道名
	resMulti := waf.CheckDenyIP(req, &innerbean.WebLog{NetSrcIp: "203.0.113.5", SRC_IP: "203.0.113.5"}, nil, h, waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME])
	if !resMulti.IsBlock || resMulti.Title != "威胁情报IP:FireHOL Level1" {
		t.Fatalf("期望拦截且 Title=威胁情报IP:FireHOL Level1，实际 %+v", resMulti)
	}

	// 3. 含 sql/bot/scan 关键词的渠道名：正常写入 Title，且 inferAttackType 必须短路返回空字符串
	resKw := waf.CheckDenyIP(req, &innerbean.WebLog{NetSrcIp: "192.0.2.8", SRC_IP: "192.0.2.8"}, nil, h, waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME])
	if !resKw.IsBlock || resKw.Title != "威胁情报IP:SQL Bot Scanner" {
		t.Fatalf("期望拦截且 Title=威胁情报IP:SQL Bot Scanner，实际 %+v", resKw)
	}
	if at := inferAttackType(resKw.Title); at != "" {
		t.Fatalf("inferAttackType(%q) 必须短路返回空字符串，实际 %q", resKw.Title, at)
	}
}
