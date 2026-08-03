package innerbean

import (
	"SamWaf/wafenginecore/ipset"
	"testing"
)

func TestRuleFunc_IPInRange(t *testing.T) {
	rf := NewRuleFunc()

	tests := []struct {
		name     string
		ip       string
		startIP  string
		endIP    string
		expected bool
	}{
		{"IP在范围内-开始", "172.16.0.0", "172.16.0.0", "172.20.255.254", true},
		{"IP在范围内-中间", "172.18.0.1", "172.16.0.0", "172.20.255.254", true},
		{"IP在范围内-结束", "172.20.255.254", "172.16.0.0", "172.20.255.254", true},
		{"IP在范围外-小于", "172.15.255.255", "172.16.0.0", "172.20.255.254", false},
		{"IP在范围外-大于", "172.21.0.0", "172.16.0.0", "172.20.255.254", false},
		{"192.168网段-在范围内", "192.168.0.100", "192.168.0.0", "192.168.1.254", true},
		{"192.168网段-不在范围内", "192.168.2.0", "192.168.0.0", "192.168.1.254", false},
		{"无效IP", "invalid", "172.16.0.0", "172.20.255.254", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rf.IPInRange(tt.ip, tt.startIP, tt.endIP)
			if result != tt.expected {
				t.Errorf("IPInRange(%s, %s, %s) = %v, want %v",
					tt.ip, tt.startIP, tt.endIP, result, tt.expected)
			}
		})
	}
}

func TestRuleFunc_IPInCIDR(t *testing.T) {
	rf := NewRuleFunc()

	tests := []struct {
		name     string
		ip       string
		cidr     string
		expected bool
	}{
		{"IP在CIDR内", "192.168.1.100", "192.168.1.0/24", true},
		{"IP不在CIDR内", "192.168.2.100", "192.168.1.0/24", false},
		{"大网段-在范围内", "10.0.50.1", "10.0.0.0/8", true},
		{"大网段-不在范围内", "11.0.0.1", "10.0.0.0/8", false},
		{"无效IP", "invalid", "192.168.1.0/24", false},
		{"无效CIDR", "192.168.1.1", "invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rf.IPInCIDR(tt.ip, tt.cidr)
			if result != tt.expected {
				t.Errorf("IPInCIDR(%s, %s) = %v, want %v",
					tt.ip, tt.cidr, result, tt.expected)
			}
		})
	}
}

func TestRuleFunc_IPInRanges(t *testing.T) {
	rf := NewRuleFunc()

	tests := []struct {
		name     string
		ip       string
		ranges   []string
		expected bool
	}{
		{
			"IP在第一个范围内",
			"172.18.0.1",
			[]string{"172.16.0.0-172.20.255.254", "192.168.0.0-192.168.1.254"},
			true,
		},
		{
			"IP在第二个范围内",
			"192.168.0.100",
			[]string{"172.16.0.0-172.20.255.254", "192.168.0.0-192.168.1.254"},
			true,
		},
		{
			"IP不在任何范围内",
			"10.0.0.1",
			[]string{"172.16.0.0-172.20.255.254", "192.168.0.0-192.168.1.254"},
			false,
		},
		{
			"混合格式-CIDR和范围",
			"192.168.1.50",
			[]string{"10.0.0.0/8", "192.168.0.0-192.168.1.254"},
			true,
		},
		{
			"混合格式-在CIDR内",
			"10.0.0.50",
			[]string{"10.0.0.0/8", "192.168.0.0-192.168.1.254"},
			true,
		},
		{
			"单个IP匹配",
			"127.0.0.1",
			[]string{"127.0.0.1", "192.168.0.1"},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rf.IPInRanges(tt.ip, tt.ranges...)
			if result != tt.expected {
				t.Errorf("IPInRanges(%s, %v) = %v, want %v",
					tt.ip, tt.ranges, result, tt.expected)
			}
		})
	}
}

func TestRuleFunc_In(t *testing.T) {
	rf := NewRuleFunc()

	tests := []struct {
		name     string
		value    string
		list     []string
		expected bool
	}{
		{"值在列表中", "GET", []string{"GET", "POST", "PUT"}, true},
		{"值不在列表中", "DELETE", []string{"GET", "POST", "PUT"}, false},
		{"空列表", "GET", []string{}, false},
		{"精确匹配", "get", []string{"GET", "POST"}, false}, // 大小写敏感
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rf.In(tt.value, tt.list...)
			if result != tt.expected {
				t.Errorf("In(%s, %v) = %v, want %v",
					tt.value, tt.list, result, tt.expected)
			}
		})
	}
}

func TestRuleFunc_InIgnoreCase(t *testing.T) {
	rf := NewRuleFunc()

	tests := []struct {
		name     string
		value    string
		list     []string
		expected bool
	}{
		{"忽略大小写匹配", "get", []string{"GET", "POST", "PUT"}, true},
		{"忽略大小写匹配2", "Get", []string{"get", "post"}, true},
		{"不匹配", "delete", []string{"GET", "POST"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rf.InIgnoreCase(tt.value, tt.list...)
			if result != tt.expected {
				t.Errorf("InIgnoreCase(%s, %v) = %v, want %v",
					tt.value, tt.list, result, tt.expected)
			}
		})
	}
}

func TestRuleFunc_ContainsAny(t *testing.T) {
	rf := NewRuleFunc()

	tests := []struct {
		name     string
		value    string
		list     []string
		expected bool
	}{
		{"包含其中一个", "Mozilla/5.0 Googlebot", []string{"bot", "spider", "crawler"}, true},
		{"包含多个", "Googlebot spider", []string{"bot", "spider"}, true},
		{"不包含任何", "Mozilla/5.0 Chrome", []string{"bot", "spider"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rf.ContainsAny(tt.value, tt.list...)
			if result != tt.expected {
				t.Errorf("ContainsAny(%s, %v) = %v, want %v",
					tt.value, tt.list, result, tt.expected)
			}
		})
	}
}

func TestRuleFunc_IntInRange(t *testing.T) {
	rf := NewRuleFunc()

	tests := []struct {
		name     string
		value    int64
		min      int64
		max      int64
		expected bool
	}{
		{"在范围内", 404, 400, 499, true},
		{"最小边界", 400, 400, 499, true},
		{"最大边界", 499, 400, 499, true},
		{"小于范围", 399, 400, 499, false},
		{"大于范围", 500, 400, 499, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rf.IntInRange(tt.value, tt.min, tt.max)
			if result != tt.expected {
				t.Errorf("IntInRange(%d, %d, %d) = %v, want %v",
					tt.value, tt.min, tt.max, result, tt.expected)
			}
		})
	}
}

func TestRuleFunc_StartsWithAny(t *testing.T) {
	rf := NewRuleFunc()

	tests := []struct {
		name     string
		value    string
		list     []string
		expected bool
	}{
		{"以其中一个开头", "/admin/users", []string{"/admin", "/api", "/manage"}, true},
		{"不以任何一个开头", "/user/profile", []string{"/admin", "/api"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rf.StartsWithAny(tt.value, tt.list...)
			if result != tt.expected {
				t.Errorf("StartsWithAny(%s, %v) = %v, want %v",
					tt.value, tt.list, result, tt.expected)
			}
		})
	}
}

func TestRuleFunc_EndsWithAny(t *testing.T) {
	rf := NewRuleFunc()

	tests := []struct {
		name     string
		value    string
		list     []string
		expected bool
	}{
		{"以其中一个结尾", "/admin/login.php", []string{".php", ".asp", ".jsp"}, true},
		{"不以任何一个结尾", "/admin/login.html", []string{".php", ".asp"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rf.EndsWithAny(tt.value, tt.list...)
			if result != tt.expected {
				t.Errorf("EndsWithAny(%s, %v) = %v, want %v",
					tt.value, tt.list, result, tt.expected)
			}
		})
	}
}

func TestRuleFunc_IPMatch(t *testing.T) {
	rf := NewRuleFunc()

	tests := []struct {
		name     string
		ip       string
		pattern  string
		expected bool
	}{
		{"单IP命中", "1.2.3.4", "1.2.3.4", true},
		{"单IP未命中", "1.2.3.5", "1.2.3.4", false},
		{"CIDR命中", "10.5.6.7", "10.0.0.0/8", true},
		{"CIDR未命中", "11.5.6.7", "10.0.0.0/8", false},
		{"IPv4尾部通配命中", "10.10.99.1", "10.10.*.*", true},
		{"IPv4尾部通配未命中", "10.11.99.1", "10.10.*.*", false},
		{"IPv4中间通配命中", "10.77.1.9", "10.*.1.*", true},
		{"IPv4中间通配未命中", "10.77.2.9", "10.*.1.*", false},
		{"区间命中起点", "1.2.3.4", "1.2.3.4-1.2.3.99", true},
		{"区间命中终点", "1.2.3.99", "1.2.3.4-1.2.3.99", true},
		{"区间未命中", "1.2.3.100", "1.2.3.4-1.2.3.99", false},
		{"IPv6单IP命中", "2001:db8::1", "2001:db8::1", true},
		{"IPv6通配命中", "2001:db8:1:2::9", "2001:db8:*:*:*:*:*:*", true},
		{"IPv6通配未命中", "2001:db9::1", "2001:db8:*:*:*:*:*:*", false},
		{"v4模式不命中v6地址", "2001:db8::1", "10.10.*.*", false},
		{"v6模式不命中v4地址", "10.10.1.1", "2001:db8:*:*:*:*:*:*", false},
		{"非法模式恒false", "1.2.3.4", "10.1*.0.0", false},
		{"非法IP恒false", "垃圾", "1.2.3.4", false},
		{"空模式恒false", "1.2.3.4", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rf.IPMatch(tt.ip, tt.pattern); got != tt.expected {
				t.Errorf("IPMatch(%s, %s) = %v, want %v", tt.ip, tt.pattern, got, tt.expected)
			}
		})
	}
}

func TestRuleFunc_IPInRanges_Wildcard(t *testing.T) {
	rf := NewRuleFunc()

	if !rf.IPInRanges("10.10.5.6", "192.168.0.0/16", "10.10.*.*") {
		t.Error("IPInRanges 应当支持通配符写法")
	}
	if !rf.IPInRanges("2001:db8::5", "10.0.0.0/8", "2001:db8:*:*:*:*:*:*") {
		t.Error("IPInRanges 应当支持 IPv6 通配符")
	}
	if rf.IPInRanges("11.10.5.6", "10.10.*.*") {
		t.Error("不匹配的通配符不应命中")
	}
	// 等价写法现在能正确命中（原实现是纯字符串比较，::ffff:1.2.3.4 与 1.2.3.4 不相等）
	if !rf.IPInRanges("::ffff:1.2.3.4", "1.2.3.4") {
		t.Error("IPInRanges 单IP项应按 IP 语义比较，v4-mapped 写法应当命中")
	}
}

func TestRuleFunc_IPInGroup(t *testing.T) {
	rf := NewRuleFunc()
	ipset.SetGroupSnapshot(nil)

	// 快照为空时不 panic、恒 false
	if rf.IPInGroup("1.2.3.4", "任意组") {
		t.Error("快照为空时 IPInGroup 应返回 false")
	}

	ipset.UpsertGroupMatcher("g-office", "办公室出口", ipset.BuildMatchSet([]string{"10.10.*.*", "1.2.3.4"}))

	if !rf.IPInGroup("10.10.1.1", "g-office") {
		t.Error("按组短码应当命中")
	}
	if !rf.IPInGroup("10.10.1.1", "办公室出口") {
		t.Error("按组名称应当命中")
	}
	if !rf.IPInGroup(" 1.2.3.4 ", "办公室出口") {
		t.Error("IP 两端空白应被容忍")
	}
	if rf.IPInGroup("172.16.0.1", "办公室出口") {
		t.Error("组外地址不应命中")
	}
	if rf.IPInGroup("10.10.1.1", "不存在的组") {
		t.Error("未知组应返回 false")
	}

	// 组内容变更后立即生效（这是 IP 组的核心契约）
	ipset.UpsertGroupMatcher("g-office", "办公室出口", ipset.BuildMatchSet([]string{"172.16.0.0/12"}))
	if rf.IPInGroup("10.10.1.1", "办公室出口") {
		t.Error("组内容已替换，旧地址不应再命中")
	}
	if !rf.IPInGroup("172.16.0.1", "办公室出口") {
		t.Error("组内容已替换，新地址应当命中")
	}

	ipset.SetGroupSnapshot(nil)
}
