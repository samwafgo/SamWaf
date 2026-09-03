package model

import "testing"

// 回归：封禁键原先只有「前缀+IP」，一个站点触发就把该 IP 在全部站点上一起封了。
// 加入作用域与站点码后，构造与解析必须能来回还原，且不能被外部输入串改作用域。

func TestBuildAndParseCCBanKey(t *testing.T) {
	cases := []struct {
		name              string
		scope, host, ip   string
		wantScope, wantIP string
		wantHost          string
	}{
		{"全局作用域", CCBanScopeGlobal, "", "1.2.3.4", CCBanScopeGlobal, "1.2.3.4", ""},
		{"全局作用域忽略站点码", CCBanScopeGlobal, "host-abc", "1.2.3.4", CCBanScopeGlobal, "1.2.3.4", ""},
		{"站点作用域", CCBanScopeHost, "host-abc", "1.2.3.4", CCBanScopeHost, "1.2.3.4", "host-abc"},
		{"非法作用域退回全局", "whatever", "host-abc", "1.2.3.4", CCBanScopeGlobal, "1.2.3.4", ""},
		{"IPv6", CCBanScopeHost, "host-abc", "2001:db8::1", CCBanScopeHost, "2001:db8::1", "host-abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := BuildCCBanKey(c.scope, c.host, c.ip)
			scope, host, ip, ok := ParseCCBanKey(key)
			if !ok {
				t.Fatalf("解析失败: %s", key)
			}
			if scope != c.wantScope || host != c.wantHost || ip != c.wantIP {
				t.Errorf("还原不一致: got(scope=%s host=%s ip=%s) want(scope=%s host=%s ip=%s)",
					scope, host, ip, c.wantScope, c.wantHost, c.wantIP)
			}
		})
	}
}

// 代理模式下客户端标识取自请求头，属于外部输入。即使它带上分隔符，
// 也只能影响自己那一段，不能伪装成别的作用域或别的站点。
func TestParseCCBanKey_UntrustedIPCannotForgeScope(t *testing.T) {
	evil := "1.2.3.4|host-victim|5.6.7.8"
	key := BuildCCBanKey(CCBanScopeHost, "host-mine", evil)
	scope, host, ip, ok := ParseCCBanKey(key)
	if !ok {
		t.Fatal("解析失败")
	}
	if scope != CCBanScopeHost {
		t.Errorf("作用域被串改为 %s", scope)
	}
	if host != "host-mine" {
		t.Errorf("站点码被串改为 %s", host)
	}
	if ip != evil {
		t.Errorf("客户端标识应完整保留，got %s", ip)
	}
}

// 升级前写入、尚未过期的旧格式键仍要能被列出与解封，否则老封禁会变成清不掉的幽灵记录。
func TestParseCCBanKey_LegacyTwoSegmentKey(t *testing.T) {
	scope, host, ip, ok := ParseCCBanKey(LegacyCCBanKey("9.9.9.9"))
	if !ok {
		t.Fatal("旧格式键解析失败")
	}
	if scope != CCBanScopeGlobal || host != "" || ip != "9.9.9.9" {
		t.Errorf("旧格式键应按全局作用域解析: scope=%s host=%s ip=%s", scope, host, ip)
	}
	if _, _, _, ok := ParseCCBanKey("SOME_OTHER_PREFIX_1.2.3.4"); ok {
		t.Error("非 CC 封禁前缀的键不应被解析成功")
	}
}

// 判定某站点的某 IP 是否被封时，全局封禁与本站点封禁都要查到。
func TestCCBanLookupKeys(t *testing.T) {
	keys := CCBanLookupKeys("host-abc", "1.2.3.4")
	if len(keys) != 2 {
		t.Fatalf("应返回全局与本站点两个键，实际 %d 个", len(keys))
	}
	if keys[0] != BuildCCBanKey(CCBanScopeGlobal, "", "1.2.3.4") {
		t.Error("缺少全局作用域键")
	}
	if keys[1] != BuildCCBanKey(CCBanScopeHost, "host-abc", "1.2.3.4") {
		t.Error("缺少本站点作用域键")
	}
}
