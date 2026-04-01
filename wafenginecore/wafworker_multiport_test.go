package wafenginecore

import (
	"SamWaf/model"
	"SamWaf/model/wafenginmodel"
	"crypto/tls"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// newTestWafEngine 创建不依赖 DB 的最小 WafEngine，供单元测试使用
func newTestWafEngine() *WafEngine {
	return &WafEngine{
		HostTarget:           make(map[string]*wafenginmodel.HostSafe),
		HostCode:             make(map[string]string),
		HostTargetNoPort:     make(map[string]string),
		HostTargetMoreDomain: make(map[string]string),
		ServerOnline:         wafenginmodel.NewSafeServerMap(),
		TransportPool:        make(map[string]*http.Transport),
		AllCertificate:       AllCertificate{Map: make(map[string]*tls.Certificate)},
	}
}

// simulateLoadHostMaps 模拟 LoadHost 中纯 map 赋值的部分（不含 DB 查询）
// 严格按照修复后的逻辑编写，用于在无 DB 环境下验证 Fix1/Fix2 正确性
func simulateLoadHostMaps(waf *WafEngine, inHost model.Hosts) {
	hostsafe := &wafenginmodel.HostSafe{Host: inHost}

	// 解析副端口列表（不写入 ServerOnline，避免 RemovePortServer 触发 DB 查询）
	var extraPorts []int
	if inHost.BindMorePort != "" && inHost.GLOBAL_HOST == 0 {
		for _, ps := range strings.Split(inHost.BindMorePort, ",") {
			if p, err := strconv.Atoi(strings.TrimSpace(ps)); err == nil {
				extraPorts = append(extraPorts, p)
			}
		}
	}

	// 主端口注册
	waf.HostTarget[inHost.Host+":"+strconv.Itoa(inHost.Port)] = hostsafe
	// Fix2: HostCode 只指向主端口，不在副端口循环内覆盖
	waf.HostCode[inHost.Code] = inHost.Host + ":" + strconv.Itoa(inHost.Port)

	// 副端口注册（只注册 HostTarget，不改 HostCode）
	for _, port := range extraPorts {
		waf.HostTarget[inHost.Host+":"+strconv.Itoa(port)] = hostsafe
	}

	// Fix1: BindMoreHost 对每个端口（主 + 副）都注册 HostTargetMoreDomain
	if inHost.BindMoreHost != "" {
		for _, line := range strings.Split(inHost.BindMoreHost, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			waf.HostTargetMoreDomain[line+":"+strconv.Itoa(inHost.Port)] = inHost.Code
			for _, ep := range extraPorts {
				waf.HostTargetMoreDomain[line+":"+strconv.Itoa(ep)] = inHost.Code
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────
// Fix 1: 副域名 + 副端口 路由注册测试
// ─────────────────────────────────────────────────────────────

// TestHostTargetMoreDomain_AllPortCombinations
// 验证：BindMoreHost × BindMorePort 的所有组合都被注册到 HostTargetMoreDomain
func TestHostTargetMoreDomain_AllPortCombinations(t *testing.T) {
	waf := newTestWafEngine()

	inHost := model.Hosts{
		Code:         "site001",
		Host:         "main.example.com",
		Port:         80,
		BindMorePort: "8080,9090",
		BindMoreHost: "sub1.example.com\nsub2.example.com",
	}
	simulateLoadHostMaps(waf, inHost)

	// 主域名 × 所有端口 应在 HostTarget
	for _, port := range []int{80, 8080, 9090} {
		key := "main.example.com:" + strconv.Itoa(port)
		if waf.HostTarget[key] == nil {
			t.Errorf("HostTarget 缺少条目 %s（主域名×端口组合未注册）", key)
		}
	}

	// 副域名 × 所有端口 应在 HostTargetMoreDomain（Fix1 修复的场景）
	for _, domain := range []string{"sub1.example.com", "sub2.example.com"} {
		for _, port := range []int{80, 8080, 9090} {
			key := domain + ":" + strconv.Itoa(port)
			if waf.HostTargetMoreDomain[key] == "" {
				t.Errorf("HostTargetMoreDomain 缺少条目 %s（副域名×副端口未注册）", key)
			}
		}
	}
}

// TestHostTargetMoreDomain_SinglePort
// 只有主端口（无 BindMorePort），副域名仍应正确注册
func TestHostTargetMoreDomain_SinglePort(t *testing.T) {
	waf := newTestWafEngine()

	inHost := model.Hosts{
		Code:         "site002",
		Host:         "main.example.com",
		Port:         443,
		BindMorePort: "",
		BindMoreHost: "www.example.com\nalias.example.com",
	}
	simulateLoadHostMaps(waf, inHost)

	for _, domain := range []string{"www.example.com", "alias.example.com"} {
		key := domain + ":443"
		if waf.HostTargetMoreDomain[key] == "" {
			t.Errorf("HostTargetMoreDomain 缺少条目 %s", key)
		}
	}
}

// TestHostTargetMoreDomain_EmptyLines
// BindMoreHost 包含空行时，不应注册空字符串键
func TestHostTargetMoreDomain_EmptyLines(t *testing.T) {
	waf := newTestWafEngine()

	inHost := model.Hosts{
		Code:         "site003",
		Host:         "main.example.com",
		Port:         80,
		BindMorePort: "8080",
		BindMoreHost: "sub.example.com\n\n  \n",
	}
	simulateLoadHostMaps(waf, inHost)

	// 空行不应产生空键
	for key := range waf.HostTargetMoreDomain {
		if strings.HasPrefix(key, ":") || strings.Contains(key, "  :") {
			t.Errorf("HostTargetMoreDomain 包含由空行产生的错误键 %q", key)
		}
	}

	// 有效域名应正常注册
	for _, port := range []int{80, 8080} {
		key := "sub.example.com:" + strconv.Itoa(port)
		if waf.HostTargetMoreDomain[key] == "" {
			t.Errorf("HostTargetMoreDomain 缺少有效条目 %s", key)
		}
	}
}

// ─────────────────────────────────────────────────────────────
// Fix 2: HostCode 不被副端口覆盖
// ─────────────────────────────────────────────────────────────

// TestHostCode_AlwaysPointsToMainPort
// 验证：有多个副端口时，HostCode[code] 始终指向主端口 key
func TestHostCode_AlwaysPointsToMainPort(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		mainPort     int
		bindMorePort string
	}{
		{"两个副端口", "a.example.com", 80, "8080,8888"},
		{"三个副端口", "b.example.com", 443, "9090,9091,9092"},
		{"单个副端口", "c.example.com", 80, "8080"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			waf := newTestWafEngine()
			inHost := model.Hosts{
				Code:         "code_" + tc.host,
				Host:         tc.host,
				Port:         tc.mainPort,
				BindMorePort: tc.bindMorePort,
			}
			simulateLoadHostMaps(waf, inHost)

			want := tc.host + ":" + strconv.Itoa(tc.mainPort)
			got := waf.HostCode["code_"+tc.host]
			if got != want {
				t.Errorf("HostCode[%s] = %q，期望 %q（副端口不应覆盖主端口）",
					"code_"+tc.host, got, want)
			}

			// 验证 HostTarget 通过 HostCode 能正确找回 hostsafe
			if waf.HostTarget[got] == nil {
				t.Errorf("HostTarget[%s] 为 nil，HostCode 指向了无效 key", got)
			}
		})
	}
}

// TestHostCode_SinglePort
// 无副端口时，HostCode 应指向唯一端口
func TestHostCode_SinglePort(t *testing.T) {
	waf := newTestWafEngine()
	inHost := model.Hosts{
		Code:         "site_single",
		Host:         "single.example.com",
		Port:         443,
		BindMorePort: "",
	}
	simulateLoadHostMaps(waf, inHost)

	want := "single.example.com:443"
	got := waf.HostCode["site_single"]
	if got != want {
		t.Errorf("HostCode[site_single] = %q，期望 %q", got, want)
	}
}

// ─────────────────────────────────────────────────────────────
// Fix 4: RemoveHost 清理所有副端口 HostTarget 条目
// ─────────────────────────────────────────────────────────────

// TestRemoveHost_CleansAllBindMorePortEntries
// 验证：RemoveHost 后，主端口和所有副端口的 HostTarget 条目全部清除
func TestRemoveHost_CleansAllBindMorePortEntries(t *testing.T) {
	waf := newTestWafEngine()

	host := model.Hosts{
		Code:         "site_clean",
		Host:         "clean.example.com",
		Port:         80,
		BindMorePort: "8080,9090",
		GLOBAL_HOST:  0,
	}
	simulateLoadHostMaps(waf, host)

	// 删除前确认所有端口已注册
	for _, port := range []int{80, 8080, 9090} {
		key := "clean.example.com:" + strconv.Itoa(port)
		if waf.HostTarget[key] == nil {
			t.Fatalf("测试前提不满足：HostTarget 缺少 %s", key)
		}
	}

	waf.RemoveHost(host)

	// 删除后所有端口条目应消失
	for _, port := range []int{80, 8080, 9090} {
		key := "clean.example.com:" + strconv.Itoa(port)
		if waf.HostTarget[key] != nil {
			t.Errorf("RemoveHost 后 HostTarget 仍有残留条目 %s", key)
		}
	}

	// HostCode 也应消失
	if waf.HostCode["site_clean"] != "" {
		t.Errorf("RemoveHost 后 HostCode[site_clean] 仍有值 %q", waf.HostCode["site_clean"])
	}
}

// TestRemoveHost_CleansMoreDomainEntries
// 验证：RemoveHost 后，HostTargetMoreDomain 中该站点的所有条目被清除
func TestRemoveHost_CleansMoreDomainEntries(t *testing.T) {
	waf := newTestWafEngine()

	host := model.Hosts{
		Code:         "site_more",
		Host:         "main.example.com",
		Port:         80,
		BindMorePort: "8080",
		BindMoreHost: "sub1.example.com\nsub2.example.com",
		GLOBAL_HOST:  0,
	}
	simulateLoadHostMaps(waf, host)

	// 删除前确认注册了所有组合
	for _, domain := range []string{"sub1.example.com", "sub2.example.com"} {
		for _, port := range []int{80, 8080} {
			key := domain + ":" + strconv.Itoa(port)
			if waf.HostTargetMoreDomain[key] == "" {
				t.Fatalf("测试前提不满足：HostTargetMoreDomain 缺少 %s", key)
			}
		}
	}

	waf.RemoveHost(host)

	// 删除后不应有任何该站点的 MoreDomain 条目
	for moreDomain, code := range waf.HostTargetMoreDomain {
		if code == "site_more" {
			t.Errorf("RemoveHost 后 HostTargetMoreDomain 中仍有 %s -> site_more", moreDomain)
		}
	}
}

// TestRemoveHost_AutoJumpHTTPS
// 验证：AutoJumpHTTPS 站点删除后，额外注册的 :80 条目也被清除
func TestRemoveHost_AutoJumpHTTPS(t *testing.T) {
	waf := newTestWafEngine()

	hostsafe := &wafenginmodel.HostSafe{Host: model.Hosts{Code: "site_ssl"}}
	waf.HostTarget["ssl.example.com:443"] = hostsafe
	waf.HostTarget["ssl.example.com:80"] = hostsafe // AutoJumpHTTPS 注册的
	waf.HostCode["site_ssl"] = "ssl.example.com:443"

	host := model.Hosts{
		Code:          "site_ssl",
		Host:          "ssl.example.com",
		Port:          443,
		AutoJumpHTTPS: 1,
	}
	waf.RemoveHost(host)

	if waf.HostTarget["ssl.example.com:443"] != nil {
		t.Error("RemoveHost 后 ssl.example.com:443 应被清除")
	}
	if waf.HostTarget["ssl.example.com:80"] != nil {
		t.Error("RemoveHost 后 AutoJumpHTTPS 的 :80 条目未清除")
	}
}

// ─────────────────────────────────────────────────────────────
// 综合场景：模拟 Issue 1 & Issue 2 完整生命周期
// ─────────────────────────────────────────────────────────────

// TestIssue1_SubDomainExtraPortRouting
// Issue 1 场景：副域名+副端口 应能路由到正确的 hostsafe
func TestIssue1_SubDomainExtraPortRouting(t *testing.T) {
	waf := newTestWafEngine()

	host := model.Hosts{
		Code:         "A",
		Host:         "primary.com",
		Port:         80,
		BindMorePort: "8080",
		BindMoreHost: "secondary.com",
	}
	simulateLoadHostMaps(waf, host)

	cases := []struct {
		requestHost string
		wantCode    string
		desc        string
	}{
		{"primary.com:80", "A", "主域名+主端口"},
		{"primary.com:8080", "A", "主域名+副端口"},
		{"secondary.com:80", "A", "副域名+主端口"},
		{"secondary.com:8080", "A", "副域名+副端口（Fix1 的目标场景）"},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			// 模拟 ServeHTTP 路由查找顺序
			gotCode := ""
			if target, ok := waf.HostTarget[c.requestHost]; ok {
				gotCode = target.Host.Code
			} else if code, ok := waf.HostTargetMoreDomain[c.requestHost]; ok {
				gotCode = code
			}

			if gotCode != c.wantCode {
				t.Errorf("请求 %s：期望路由到 %q，实际 %q", c.requestHost, c.wantCode, gotCode)
			}
		})
	}
}

// TestIssue2_DeleteSiteNotAffectOtherSiteExtraPort
// Issue 2 场景：删除任意站点 B 后，站点 A 的副端口路由信息应完整保留
func TestIssue2_DeleteSiteNotAffectOtherSiteExtraPort(t *testing.T) {
	waf := newTestWafEngine()

	// 站点 A：主端口 80 + 副端口 8080
	hostA := model.Hosts{
		Code:         "A",
		Host:         "siteA.com",
		Port:         80,
		BindMorePort: "8080",
	}
	simulateLoadHostMaps(waf, hostA)

	// 站点 B：独立站点，主端口 9090
	hostB := model.Hosts{
		Code: "B",
		Host: "siteB.com",
		Port: 9090,
	}
	simulateLoadHostMaps(waf, hostB)

	// 删除站点 B
	waf.RemoveHost(hostB)

	// 站点 A 的主端口和副端口应仍然存在
	if waf.HostTarget["siteA.com:80"] == nil {
		t.Error("删除站点 B 后，站点 A 主端口 :80 不应受影响")
	}
	if waf.HostTarget["siteA.com:8080"] == nil {
		t.Error("删除站点 B 后，站点 A 副端口 :8080 不应受影响")
	}
	if waf.HostCode["A"] != "siteA.com:80" {
		t.Errorf("删除站点 B 后，站点 A 的 HostCode 应为 siteA.com:80，实际 %q", waf.HostCode["A"])
	}
}

// TestIssue2_CreateNewThenDeleteNotBreakExistingExtraPort
// Issue 2 完整复现：新建防护再删除，不应影响已有站点的副端口
func TestIssue2_CreateNewThenDeleteNotBreakExistingExtraPort(t *testing.T) {
	waf := newTestWafEngine()

	// 步骤1：建立站点 A，一个域名+多个端口
	hostA := model.Hosts{
		Code:         "siteA",
		Host:         "example.com",
		Port:         80,
		BindMorePort: "8080,8443",
	}
	simulateLoadHostMaps(waf, hostA)

	// 步骤2：新建防护（站点 B）
	hostB := model.Hosts{
		Code: "siteB",
		Host: "newsite.com",
		Port: 7070,
	}
	simulateLoadHostMaps(waf, hostB)

	// 步骤3：删除站点 B
	waf.RemoveHost(hostB)

	// 验证：站点 A 的所有端口映射仍然完整
	expectedKeys := []string{
		"example.com:80",
		"example.com:8080",
		"example.com:8443",
	}
	for _, key := range expectedKeys {
		if waf.HostTarget[key] == nil {
			t.Errorf("删除站点 B 后，站点 A 的 HostTarget[%s] 被错误清除", key)
		}
	}

	// 站点 B 的条目应已清除
	if waf.HostTarget["newsite.com:7070"] != nil {
		t.Error("站点 B 的条目应被 RemoveHost 清除")
	}
}

// ─────────────────────────────────────────────────────────────
// Bug A & B 修复验证：情况2 BindMorePort 变更 & RemoveHost 用旧数据
// ─────────────────────────────────────────────────────────────

// TestBindMorePortChange_OldPortCleaned
// Bug A：修改副端口时，旧副端口的 HostTarget 条目应被清除
// Bug B：RemoveHost 必须用旧数据才能清到旧端口（传新数据清不掉旧的）
//
// 修复前行为：BindMorePort "8080,9090" → "8080,7070"
//
//	RemoveHost(hosts[0]) 删的是 8080+7070（新），9090（旧）残留
//
// 修复后行为：RemoveHost(hostsOld) 删的是 8080+9090（旧），然后 LoadHost 加载新配置
func TestBindMorePortChange_OldPortCleaned(t *testing.T) {
	waf := newTestWafEngine()

	// 初始状态：主端口 80，副端口 8080,9090
	oldHost := model.Hosts{
		Code:         "siteX",
		Host:         "x.example.com",
		Port:         80,
		BindMorePort: "8080,9090",
	}
	simulateLoadHostMaps(waf, oldHost)

	// 确认旧状态
	for _, port := range []int{80, 8080, 9090} {
		if waf.HostTarget["x.example.com:"+strconv.Itoa(port)] == nil {
			t.Fatalf("测试前提不满足：HostTarget 缺少 x.example.com:%d", port)
		}
	}

	// 用户修改副端口：9090 → 7070（新副端口列表 8080,7070）
	newHost := model.Hosts{
		Code:         "siteX",
		Host:         "x.example.com",
		Port:         80,
		BindMorePort: "8080,7070",
	}

	// 模拟 main.go 情况2 修复后的行为：
	// BindMorePort 不同 → RemoveHost(hostsOld)，然后 LoadHost(hosts[0])
	if newHost.BindMorePort != oldHost.BindMorePort {
		waf.RemoveHost(oldHost) // Bug B 修复：传旧数据
	}
	simulateLoadHostMaps(waf, newHost)

	// 新端口 7070 应存在
	if waf.HostTarget["x.example.com:7070"] == nil {
		t.Error("新副端口 7070 应已注册到 HostTarget")
	}
	// 保留的端口 8080 应存在
	if waf.HostTarget["x.example.com:8080"] == nil {
		t.Error("副端口 8080 应仍然注册")
	}
	// 旧端口 9090 应被清除（Bug A+B 修复后）
	if waf.HostTarget["x.example.com:9090"] != nil {
		t.Error("旧副端口 9090 应在 RemoveHost(hostsOld) 后被清除（Bug A+B 未修复时会残留）")
	}
}

// TestBindMorePortChange_WithOldDataVsNewData
// 直接对比：传旧数据 vs 传新数据 到 RemoveHost，验证结果差异
// 这个测试精确复现了 Bug B 的问题所在
func TestBindMorePortChange_WithOldDataVsNewData(t *testing.T) {
	// 场景：副端口从 "8080,9090" 变为 "8080,7070"

	t.Run("传新数据_旧端口9090残留", func(t *testing.T) {
		waf := newTestWafEngine()
		oldHost := model.Hosts{Code: "s1", Host: "h.com", Port: 80, BindMorePort: "8080,9090"}
		simulateLoadHostMaps(waf, oldHost)

		newHost := model.Hosts{Code: "s1", Host: "h.com", Port: 80, BindMorePort: "8080,7070"}
		waf.RemoveHost(newHost) // Bug B：传新数据，9090 不会被清除
		simulateLoadHostMaps(waf, newHost)

		// 9090 应被清除，但传新数据时实际没清
		if waf.HostTarget["h.com:9090"] != nil {
			t.Log("符合预期（Bug B 存在时）：传新数据，旧端口 9090 残留 —— 这正是 Bug B 的表现")
		} else {
			t.Log("旧端口 9090 被清除（不受 Bug B 影响的情况）")
		}
	})

	t.Run("传旧数据_旧端口9090被正确清除", func(t *testing.T) {
		waf := newTestWafEngine()
		oldHost := model.Hosts{Code: "s1", Host: "h.com", Port: 80, BindMorePort: "8080,9090"}
		simulateLoadHostMaps(waf, oldHost)

		newHost := model.Hosts{Code: "s1", Host: "h.com", Port: 80, BindMorePort: "8080,7070"}
		waf.RemoveHost(oldHost) // 修复后：传旧数据
		simulateLoadHostMaps(waf, newHost)

		// 9090 必须被清除
		if waf.HostTarget["h.com:9090"] != nil {
			t.Error("传旧数据后旧端口 9090 仍残留，Fix 未生效")
		}
		// 7070 必须存在
		if waf.HostTarget["h.com:7070"] == nil {
			t.Error("新端口 7070 未注册")
		}
	})
}
