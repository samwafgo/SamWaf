package model

import "testing"

func TestRuleBanKeyRoundTrip(t *testing.T) {
	key := BuildRuleBanKey("host-code-1", "1.2.3.4")
	hostCode, ip, ok := ParseRuleBanKey(key)
	if !ok || hostCode != "host-code-1" || ip != "1.2.3.4" {
		t.Fatalf("回环解析失败: hostCode=%q ip=%q ok=%v", hostCode, ip, ok)
	}
}

func TestRuleBanKeyIPv6(t *testing.T) {
	key := BuildRuleBanKey("host-code-1", "2001:db8::1")
	hostCode, ip, ok := ParseRuleBanKey(key)
	if !ok || hostCode != "host-code-1" || ip != "2001:db8::1" {
		t.Fatalf("IPv6 回环解析失败: hostCode=%q ip=%q ok=%v", hostCode, ip, ok)
	}
}

func TestRuleBanKeyRejectForeignPrefix(t *testing.T) {
	if _, _, ok := ParseRuleBanKey("CACHE_CCVISITBAN_PRE_global|host|1.2.3.4"); ok {
		t.Fatalf("非规则封禁前缀被误解析")
	}
}

func TestRuleBanKeyRejectMalformed(t *testing.T) {
	// 缺少分隔符
	if _, _, ok := ParseRuleBanKey("CACHE_RULE_BAN_PRE_1.2.3.4"); ok {
		t.Fatalf("缺少站点分隔符被误解析")
	}
	// 站点码为空
	if _, _, ok := ParseRuleBanKey("CACHE_RULE_BAN_PRE_|1.2.3.4"); ok {
		t.Fatalf("空站点码被误解析")
	}
}
