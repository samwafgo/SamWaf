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
