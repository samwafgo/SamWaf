package wafenginecore

// 引擎侧「IP 组 + 泛解析(通配符/区间)」用例。
//
// 最核心的一条是 TestCheckDenyIP_Group_ChangeTakesEffectWithoutHostReload：
// 它钉死整个方案的契约——改组内容只替换 ipset 全局快照，完全不碰 HostSafe，
// 所有引用该组的站点(含全局网站)立即生效。如果哪天有人把组内容展开进 HostSafe，
// 这条用例仍会通过，但 TestCheckDenyIP_Group_GlobalHostSharesSameGroup 那种
// 「一次改动多站点同时生效」的语义会退化成需要逐站点下发，那时应当重新审视本文件的注释。

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

// newIPGroupTestEngine 造一个含全局网站与两个普通站点的引擎。
// globalGuard 决定全局网站是否开启防护（关闭时全局名单不参与判定）。
func newIPGroupTestEngine(t *testing.T, globalGuard int) *WafEngine {
	t.Helper()
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "json")

	oldGlobalName := global.GWAF_GLOBAL_HOST_NAME
	global.GWAF_GLOBAL_HOST_NAME = "全局网站:0"
	t.Cleanup(func() {
		global.GWAF_GLOBAL_HOST_NAME = oldGlobalName
		ipset.SetGroupSnapshot(nil)
	})

	waf := &WafEngine{}
	waf.InitRouting()
	waf.withWriteTable(func(nt *routingTable) {
		nt.HostTarget[global.GWAF_GLOBAL_HOST_NAME] = &wafenginmodel.HostSafe{
			Host: model.Hosts{Code: "codeGlobal", GUARD_STATUS: globalGuard},
		}
		nt.HostCode["codeGlobal"] = global.GWAF_GLOBAL_HOST_NAME
		nt.HostTarget["a.com:80"] = &wafenginmodel.HostSafe{
			Host: model.Hosts{Code: "codeA", Host: "a.com", GUARD_STATUS: 1},
		}
		nt.HostCode["codeA"] = "a.com:80"
		nt.HostTarget["b.com:80"] = &wafenginmodel.HostSafe{
			Host: model.Hosts{Code: "codeB", Host: "b.com", GUARD_STATUS: 1},
		}
		nt.HostCode["codeB"] = "b.com:80"
	})
	return waf
}

func denyBlocked(t *testing.T, waf *WafEngine, hostCode, clientIP string) bool {
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

func allowJumped(t *testing.T, waf *WafEngine, hostCode, clientIP string) bool {
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
	return waf.CheckAllowIP(req, weblog, nil, h, waf.rt().HostTarget[global.GWAF_GLOBAL_HOST_NAME]).JumpGuardResult
}

// setBlockList 模拟 main.go 收到 ChanTypeBlockIP 后的完整动作
func setBlockList(waf *WafEngine, hostCode string, list []model.IPBlockList) {
	index := BuildIPBlockIndex(list)
	codes := ExtractBlockGroupCodes(list)
	waf.UpdateHost(hostCode, func(h *wafenginmodel.HostSafe) {
		h.IPBlockLists = list
		h.IPBlockIndex = index
		h.IPBlockGroupCodes = codes
	})
}

func setAllowList(waf *WafEngine, hostCode string, list []model.IPAllowList) {
	index := BuildIPAllowIndex(list)
	codes := ExtractAllowGroupCodes(list)
	waf.UpdateHost(hostCode, func(h *wafenginmodel.HostSafe) {
		h.IPWhiteLists = list
		h.IPWhiteIndex = index
		h.IPWhiteGroupCodes = codes
	})
}

// ---------- 泛解析（通配符 / 区间） ----------

func TestCheckDenyIP_Wildcard(t *testing.T) {
	waf := newIPGroupTestEngine(t, 0)
	setBlockList(waf, "codeA", []model.IPBlockList{
		{Ip: "10.10.*.*"},
		{Ip: "192.168.1.10-192.168.1.20"},
		{Ip: "2001:db8:*:*:*:*:*:*"},
	})

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.10.1.1", true},
		{"10.11.1.1", false},
		{"192.168.1.15", true},
		{"192.168.1.9", false},
		{"192.168.1.21", false},
		{"2001:db8::1", true},
		{"2001:db9::1", false},
	}
	for _, c := range cases {
		if got := denyBlocked(t, waf, "codeA", c.ip); got != c.want {
			t.Errorf("黑名单对 %s 判定 = %v, want %v", c.ip, got, c.want)
		}
	}
}

// 线性回退路径也必须支持通配符与区间。
// 只给 IPBlockLists 不给 Index，模拟索引未构建的旧路径——
// 若 matchDenyIP 的回退分支还在用 CheckIPInCIDR（只认单IP与CIDR），本用例会失败。
func TestCheckDenyIP_LinearFallbackWildcard(t *testing.T) {
	waf := newIPGroupTestEngine(t, 0)
	waf.UpdateHost("codeA", func(h *wafenginmodel.HostSafe) {
		h.IPBlockLists = []model.IPBlockList{
			{Ip: "10.10.*.*"},
			{Ip: "192.168.1.10-192.168.1.20"},
		}
		h.IPBlockIndex = nil // 关键：不构建索引，强制走线性回退
	})

	if !denyBlocked(t, waf, "codeA", "10.10.5.5") {
		t.Error("线性回退路径应当支持通配符")
	}
	if !denyBlocked(t, waf, "codeA", "192.168.1.15") {
		t.Error("线性回退路径应当支持区间")
	}
	if denyBlocked(t, waf, "codeA", "10.11.5.5") {
		t.Error("线性回退路径不应误拦通配符之外的地址")
	}
}

func TestCheckAllowIP_Wildcard(t *testing.T) {
	waf := newIPGroupTestEngine(t, 0)
	setAllowList(waf, "codeA", []model.IPAllowList{{Ip: "172.16.*.*"}})

	if !allowJumped(t, waf, "codeA", "172.16.9.9") {
		t.Error("白名单通配符应当放行")
	}
	if allowJumped(t, waf, "codeA", "172.17.9.9") {
		t.Error("白名单不应放行通配符之外的地址")
	}
}

// ---------- IP 组 ----------

func TestCheckDenyIP_Group(t *testing.T) {
	waf := newIPGroupTestEngine(t, 0)
	ipset.UpsertGroupMatcher("g1", "扫描器段", ipset.BuildMatchSet([]string{"10.10.*.*", "1.2.3.4"}))
	setBlockList(waf, "codeA", []model.IPBlockList{
		{IpType: model.IPEntryTypeGroup, GroupCode: "g1"},
	})

	if !denyBlocked(t, waf, "codeA", "10.10.1.1") {
		t.Error("引用IP组的黑名单应当拦截组内地址")
	}
	if !denyBlocked(t, waf, "codeA", "1.2.3.4") {
		t.Error("引用IP组的黑名单应当拦截组内单IP")
	}
	if denyBlocked(t, waf, "codeA", "8.8.8.8") {
		t.Error("组外地址不应被拦截")
	}
	// 没有引用该组的站点不受影响
	if denyBlocked(t, waf, "codeB", "10.10.1.1") {
		t.Error("未引用该组的站点不应被影响")
	}
}

// 整个方案的核心契约：改组内容只替换 ipset 全局快照，不碰 HostSafe，判定结果立即改变。
// 若哪天有人把组内容展开进了 HostSafe.IPBlockIndex，本用例会失败。
func TestCheckDenyIP_Group_ChangeTakesEffectWithoutHostReload(t *testing.T) {
	waf := newIPGroupTestEngine(t, 0)
	ipset.UpsertGroupMatcher("g1", "扫描器段", ipset.BuildMatchSet([]string{"10.10.*.*"}))
	setBlockList(waf, "codeA", []model.IPBlockList{
		{IpType: model.IPEntryTypeGroup, GroupCode: "g1"},
	})

	if !denyBlocked(t, waf, "codeA", "10.10.1.1") {
		t.Fatal("前置条件：应先命中")
	}

	// 只改组内容，绝不触碰 HostSafe / 路由表
	snapshotBefore := waf.rt()
	ipset.UpsertGroupMatcher("g1", "扫描器段", ipset.BuildMatchSet([]string{"172.16.0.0/12"}))
	if waf.rt() != snapshotBefore {
		t.Fatal("改组内容不应导致路由快照发生变化")
	}

	if denyBlocked(t, waf, "codeA", "10.10.1.1") {
		t.Error("组内容已替换，旧地址不应再被拦截（说明组内容被固化进了 HostSafe）")
	}
	if !denyBlocked(t, waf, "codeA", "172.16.1.1") {
		t.Error("组内容已替换，新地址应当立即被拦截")
	}
}

// 多个站点(含全局网站)引用同一个组时，改一次组要让它们同时生效
func TestCheckDenyIP_Group_GlobalHostSharesSameGroup(t *testing.T) {
	waf := newIPGroupTestEngine(t, 1) // 全局网站开启防护
	ipset.UpsertGroupMatcher("shared", "共享组", ipset.BuildMatchSet([]string{"10.10.*.*"}))

	// A 站点自己引用；B 站点不引用，但全局网站引用了同一个组
	setBlockList(waf, "codeA", []model.IPBlockList{{IpType: model.IPEntryTypeGroup, GroupCode: "shared"}})
	setBlockList(waf, "codeGlobal", []model.IPBlockList{{IpType: model.IPEntryTypeGroup, GroupCode: "shared"}})

	if !denyBlocked(t, waf, "codeA", "10.10.1.1") {
		t.Error("A 站点应当拦截")
	}
	if !denyBlocked(t, waf, "codeB", "10.10.1.1") {
		t.Error("B 站点应当经由全局网站的组引用被拦截")
	}

	// 一次改动，两个站点同时改变判定
	ipset.UpsertGroupMatcher("shared", "共享组", ipset.BuildMatchSet([]string{"1.1.1.1"}))
	if denyBlocked(t, waf, "codeA", "10.10.1.1") || denyBlocked(t, waf, "codeB", "10.10.1.1") {
		t.Error("改一次组后，所有引用站点都应立即停止拦截旧地址")
	}
	if !denyBlocked(t, waf, "codeA", "1.1.1.1") || !denyBlocked(t, waf, "codeB", "1.1.1.1") {
		t.Error("改一次组后，所有引用站点都应立即拦截新地址")
	}
}

// 全局网站关闭防护时，它的组引用不参与判定
func TestCheckDenyIP_Group_GlobalHostGuardOff(t *testing.T) {
	waf := newIPGroupTestEngine(t, 0) // 全局网站 GUARD_STATUS=0
	ipset.UpsertGroupMatcher("shared", "共享组", ipset.BuildMatchSet([]string{"10.10.*.*"}))
	setBlockList(waf, "codeGlobal", []model.IPBlockList{{IpType: model.IPEntryTypeGroup, GroupCode: "shared"}})

	if denyBlocked(t, waf, "codeB", "10.10.1.1") {
		t.Error("全局网站未开启防护时，其组引用不应生效")
	}
}

// 组已被删除但引用行还没清理时：不能 panic，也不能误拦
func TestCheckDenyIP_GroupMissing(t *testing.T) {
	waf := newIPGroupTestEngine(t, 0)
	ipset.SetGroupSnapshot(nil) // 快照完全为空
	setBlockList(waf, "codeA", []model.IPBlockList{
		{IpType: model.IPEntryTypeGroup, GroupCode: "已删除的组"},
	})

	if denyBlocked(t, waf, "codeA", "10.10.1.1") {
		t.Error("引用了不存在的组时不应拦截")
	}
}

func TestCheckAllowIP_Group(t *testing.T) {
	waf := newIPGroupTestEngine(t, 0)
	ipset.UpsertGroupMatcher("office", "办公室出口", ipset.BuildMatchSet([]string{"203.0.113.0/24"}))
	setAllowList(waf, "codeA", []model.IPAllowList{
		{IpType: model.IPEntryTypeGroup, GroupCode: "office"},
	})

	if !allowJumped(t, waf, "codeA", "203.0.113.9") {
		t.Error("引用IP组的白名单应当放行组内地址")
	}
	if allowJumped(t, waf, "codeA", "8.8.8.8") {
		t.Error("组外地址不应被放行")
	}

	// 白名单侧同样要求「改组即时生效」——这里更关键，晚生效等于误拦合法用户
	ipset.UpsertGroupMatcher("office", "办公室出口", ipset.BuildMatchSet([]string{"198.51.100.0/24"}))
	if allowJumped(t, waf, "codeA", "203.0.113.9") {
		t.Error("组内容已替换，旧地址不应再被放行")
	}
	if !allowJumped(t, waf, "codeA", "198.51.100.9") {
		t.Error("组内容已替换，新地址应当立即被放行")
	}
}

// 混合条目：同一站点同时有「单条」与「引用组」两种行
func TestCheckDenyIP_MixedEntries(t *testing.T) {
	waf := newIPGroupTestEngine(t, 0)
	ipset.UpsertGroupMatcher("g1", "组一", ipset.BuildMatchSet([]string{"10.10.*.*"}))
	setBlockList(waf, "codeA", []model.IPBlockList{
		{Ip: "1.2.3.4"}, // 存量行：ip_type 为空
		{Ip: "5.6.7.0/24", IpType: model.IPEntryTypeIP},   // 显式单条
		{IpType: model.IPEntryTypeGroup, GroupCode: "g1"}, // 组引用
	})

	for _, ip := range []string{"1.2.3.4", "5.6.7.99", "10.10.1.1"} {
		if !denyBlocked(t, waf, "codeA", ip) {
			t.Errorf("混合名单应当拦截 %s", ip)
		}
	}
	if denyBlocked(t, waf, "codeA", "8.8.8.8") {
		t.Error("混合名单不应误拦 8.8.8.8")
	}
}

// 存量兼容：ip_type 为空串的行必须仍按「单条IP」处理。
// 若判定处写成 != IPEntryTypeIP，存量行会被全部当成组引用而失效，本用例即失败。
func TestBuildIndex_LegacyEmptyIpTypeStillCounts(t *testing.T) {
	list := []model.IPBlockList{
		{Ip: "1.2.3.4"},             // 存量行
		{Ip: "5.6.7.8", IpType: ""}, // 显式空串
	}
	index := BuildIPBlockIndex(list)
	if index == nil {
		t.Fatal("存量行不应产出 nil 索引")
	}
	if index.Len() != 2 {
		t.Errorf("存量行应全部进索引，Len() = %d, want 2", index.Len())
	}
	if len(ExtractBlockGroupCodes(list)) != 0 {
		t.Error("存量行不应被识别为组引用")
	}
}

func TestExtractGroupCodes_Dedup(t *testing.T) {
	list := []model.IPBlockList{
		{IpType: model.IPEntryTypeGroup, GroupCode: "g1"},
		{IpType: model.IPEntryTypeGroup, GroupCode: "g2"},
		{IpType: model.IPEntryTypeGroup, GroupCode: "g1"}, // 重复
		{IpType: model.IPEntryTypeGroup, GroupCode: ""},   // 空码，应忽略
		{Ip: "1.2.3.4"},
	}
	codes := ExtractBlockGroupCodes(list)
	if len(codes) != 2 || codes[0] != "g1" || codes[1] != "g2" {
		t.Errorf("ExtractBlockGroupCodes = %v, want [g1 g2]（去重且保持顺序）", codes)
	}
	// 组引用行不进索引
	index := BuildIPBlockIndex(list)
	if index.Len() != 1 {
		t.Errorf("只有 1 条单条行应进索引，Len() = %d", index.Len())
	}
}
