package ipset

import (
	"fmt"
	"net"
	"testing"
)

func TestMatchSetExactAndCIDR(t *testing.T) {
	m := BuildMatchSet([]string{
		"1.2.3.4",            // 单 v4
		"10.0.0.0/8",         // v4 段
		"192.168.1.0/24",     // v4 段
		"2001:db8::1",        // 单 v6
		"2001:db8:abcd::/48", // v6 段
		"  ",                 // 空白，应跳过
		"not-an-ip",          // 非法，应跳过
		"5.6.7.0/33",         // 非法掩码，应跳过
	})

	cases := []struct {
		ip   string
		want bool
	}{
		{"1.2.3.4", true},               // 精确命中
		{"1.2.3.5", false},              // 不在任何集合
		{"10.255.255.255", true},        // 10/8 覆盖
		{"11.0.0.1", false},             // 相邻段不覆盖
		{"192.168.1.200", true},         // /24 覆盖
		{"192.168.2.1", false},          // 相邻 /24 不覆盖
		{"2001:db8::1", true},           // v6 精确
		{"2001:db8::2", false},          // v6 未命中
		{"2001:db8:abcd:1234::9", true}, // v6 /48 覆盖
		{"2001:db8:abce::1", false},     // v6 相邻不覆盖
		{"", false},
	}
	for _, c := range cases {
		got := m.Contains(net.ParseIP(c.ip))
		if got != c.want {
			t.Errorf("Contains(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestMatchSetNilSafe(t *testing.T) {
	var m *MatchSet
	if m.Contains(net.ParseIP("1.1.1.1")) {
		t.Error("nil MatchSet should not match")
	}
	if m.ContainsStr("1.1.1.1") {
		t.Error("nil MatchSet ContainsStr should not match")
	}
	if m.Len() != 0 {
		t.Error("nil MatchSet Len should be 0")
	}
}

func TestMatchSetDefaultRoute(t *testing.T) {
	m := BuildMatchSet([]string{"0.0.0.0/0"})
	if !m.Contains(net.ParseIP("8.8.8.8")) {
		t.Error("0.0.0.0/0 should cover all v4")
	}
	if m.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("0.0.0.0/0 should not cover v6")
	}
}

func TestMatchSetWildcard(t *testing.T) {
	m := BuildMatchSet([]string{
		"10.10.*.*",            // 尾部通配（可降级 CIDR，走前缀树）
		"172.*.5.*",            // 掩码不连续（走线性表）
		"2001:db8:*:*:*:*:*:*", // IPv6 通配
	})
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.10.0.1", true},
		{"10.10.255.255", true},
		{"10.11.0.1", false},
		{"172.16.5.9", true},   // 第 2、4 段任意，第 3 段必须是 5
		{"172.200.5.1", true},  //
		{"172.16.6.9", false},  // 第 3 段不是 5
		{"2001:db8::1", true},  //
		{"2001:db9::1", false}, //
		{"10.10.1.1", true},
	}
	for _, c := range cases {
		if got := m.Contains(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("Contains(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestMatchSetRange(t *testing.T) {
	m := BuildMatchSet([]string{
		"1.2.3.4-1.2.3.99",
		"2001:db8::10-2001:db8::20",
	})
	cases := []struct {
		ip   string
		want bool
	}{
		{"1.2.3.3", false}, // 起点前一个
		{"1.2.3.4", true},  // 起点
		{"1.2.3.50", true}, // 中间
		{"1.2.3.99", true}, // 终点
		{"1.2.3.100", false},
		{"2001:db8::f", false},
		{"2001:db8::10", true},
		{"2001:db8::20", true},
		{"2001:db8::21", false},
	}
	for _, c := range cases {
		if got := m.Contains(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("Contains(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// v4 与 v6 必须严格隔离，任何一方的模式都不能命中另一方的地址
func TestMatchSetFamilyIsolation(t *testing.T) {
	m4 := BuildMatchSet([]string{"10.*.1.*", "10.0.0.0/8", "1.2.3.4-1.2.3.9"})
	if m4.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("纯 v4 集合不应命中 v6 地址")
	}
	m6 := BuildMatchSet([]string{"2001:db8:*:*:*:*:*:*", "2001:db8::/32"})
	if m6.Contains(net.ParseIP("10.0.1.1")) {
		t.Error("纯 v6 集合不应命中 v4 地址")
	}
	// v4-mapped 写法按 v4 处理（与历史行为一致）
	if !m4.Contains(net.ParseIP("::ffff:10.5.1.7")) {
		t.Error("v4-mapped 地址应当按 v4 判定并命中 10.*.1.*")
	}
}

// 回归钉子：Contains 的三层判定必须逐层短路而不是某层直接 return。
// 构造一个只含「不连续掩码通配符」的集合——若 cidr4 那层写成 return，本用例必失败。
func TestMatchSetContainsOrderNotShortCircuited(t *testing.T) {
	m := BuildMatchSet([]string{"10.*.1.*"})
	if len(m.exact4) != 0 {
		t.Fatal("前置条件被破坏：集合不应含精确项")
	}
	if !m.Contains(net.ParseIP("10.99.1.99")) {
		t.Error("只含通配符的集合未命中——Contains 很可能在 cidr 层直接 return 了，通配符线性表永远走不到")
	}

	// v6 同理
	m6 := BuildMatchSet([]string{"2001:*:1:*:*:*:*:*"})
	if !m6.Contains(net.ParseIP("2001:ffff:1:2::9")) {
		t.Error("v6 只含通配符的集合未命中——Contains v6 分支同样漏拆 return")
	}
}

func TestMatchSetStats(t *testing.T) {
	m := BuildMatchSet([]string{
		"1.2.3.4",          // Exact
		"2001:db8::1",      // Exact
		"10.0.0.0/8",       // CIDR
		"10.10.*.*",        // Wildcard
		"172.*.5.*",        // Wildcard
		"1.2.3.4-1.2.3.99", // Range
		"not-an-ip",        // Dropped
		"10.1*.0.0",        // Dropped
		"  ",               // Dropped
	})
	got := m.Stats()
	want := Stats{Exact: 2, CIDR: 1, Wildcard: 2, Range: 1, Dropped: 3}
	if got != want {
		t.Errorf("Stats() = %+v, want %+v", got, want)
	}
	if m.Len() != 6 {
		t.Errorf("Len() = %d, want 6（只统计成功收录的）", m.Len())
	}
	if m.WildcardLen() != 1 {
		t.Errorf("WildcardLen() = %d, want 1（只有 172.*.5.* 掩码不连续走线性表）", m.WildcardLen())
	}
	if !m.HasWildcard() {
		t.Error("HasWildcard() 应为 true")
	}
	if BuildMatchSet([]string{"1.2.3.4", "10.0.0.0/8"}).HasWildcard() {
		t.Error("只含单 IP 与 CIDR 的集合 HasWildcard() 应为 false（可下发系统防火墙）")
	}
}

// 简单基准：十万条 CIDR 下的单次查询代价
func BenchmarkMatchSetContains100k(b *testing.B) {
	items := make([]string, 0, 100000)
	for i := 0; i < 100000; i++ {
		items = append(items, fmt.Sprintf("%d.%d.%d.0/24", 10+(i>>16)&0xff, (i>>8)&0xff, i&0xff))
	}
	m := BuildMatchSet(items)
	target := net.ParseIP("203.0.113.1") // 未命中，走到最深
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Contains(target)
	}
}

// 基准：1000 条不连续掩码通配符（只能线性匹配）下的未命中代价，
// 用来给「通配符条数告警阈值」定经验值。
func BenchmarkMatchSetWildcard1k(b *testing.B) {
	items := make([]string, 0, 1000)
	for i := 0; i < 1000; i++ {
		items = append(items, fmt.Sprintf("10.*.%d.*", i%256))
	}
	m := BuildMatchSet(items)
	target := net.ParseIP("203.0.113.1") // 未命中，扫完整个线性表
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Contains(target)
	}
}
