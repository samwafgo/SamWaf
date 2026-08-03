package ipset

import (
	"bytes"
	"errors"
	"math/rand"
	"net"
	"strings"
	"testing"
)

func TestParsePattern_Valid(t *testing.T) {
	cases := []struct {
		raw        string
		wantKind   PatternKind
		wantWidth  int
		wantPrefix int
	}{
		{"1.2.3.4", KindSingle, 4, 32},
		{"2001:db8::1", KindSingle, 16, 128},
		{"1.2.3.0/24", KindCIDR, 4, 24},
		{"2001:db8::/32", KindCIDR, 16, 32},
		{"10.10.*.*", KindWildcard, 4, 16},             // 尾部通配 → 可降级 CIDR
		{"10.*.*.*", KindWildcard, 4, 8},               // 等价 10.0.0.0/8
		{"10.*.1.*", KindWildcard, 4, -1},              // 掩码不连续 → 线性表
		{"*.*.*.*", KindWildcard, 4, 0},                // 全通配：语法合法，写入侧另行拒绝
		{"192.168.1.*", KindWildcard, 4, 24},           //
		{"2001:db8:*:*:*:*:*:*", KindWildcard, 16, 32}, //
		{"1.2.3.4-1.2.3.99", KindRange, 4, -1},         //
		{"2001:db8::1-2001:db8::ff", KindRange, 16, -1},
		{"1.2.3.4-1.2.3.4", KindSingle, 4, 32}, // 起止相同 → 退化单 IP
		{"  1.2.3.4  ", KindSingle, 4, 32},     // 两端空白
	}
	for _, c := range cases {
		p, err := ParsePattern(c.raw)
		if err != nil {
			t.Errorf("ParsePattern(%q) 意外报错: %v", c.raw, err)
			continue
		}
		if p.Kind != c.wantKind || p.Width != c.wantWidth || p.Prefix != c.wantPrefix {
			t.Errorf("ParsePattern(%q) = kind=%d width=%d prefix=%d, want kind=%d width=%d prefix=%d",
				c.raw, p.Kind, p.Width, p.Prefix, c.wantKind, c.wantWidth, c.wantPrefix)
		}
	}
}

func TestParsePattern_Invalid(t *testing.T) {
	cases := []string{
		"",                       // 空
		"   ",                    // 全空白
		"not-an-ip",              // 含 '-' 走区间分支，两端都不是 IP
		"5.6.7.0/33",             // 非法掩码
		"2001:db8::*",            // :: 与 * 混用
		"2001:db8:*:*",           // IPv6 通配段数不足
		"2001:db8:*:*:*:*:*:*:*", // IPv6 通配段数超出
		"::ffff:10.10.*.*",       // 内嵌 IPv4 + ::
		"10.*.*.*/8",             // 通配符带掩码
		"10.1*.0.0",              // 段内部分通配
		"10.10.*",                // IPv4 通配段数不足
		"10.10.*.*.*",            // IPv4 通配段数超出
		"10.256.*.*",             // 段超出 0-255
		"10.010.*.*",             // 前导零
		"1.2.3.4-::1",            // 跨族区间
		"1.2.3.*-1.2.3.9",        // 区间内含通配符
		"1.2.3.0/24-1.2.3.9",     // 区间内含掩码
		"-1.2.3.4",               // 区间缺起点
		"1.2.3.4-",               // 区间缺终点
	}
	for _, raw := range cases {
		if _, err := ParsePattern(raw); err == nil {
			t.Errorf("ParsePattern(%q) 应当报错，但通过了", raw)
		}
	}
}

// 区间起止颠倒：严格解析必须报错（挡住新数据），宽容解析自动交换（存量数据仍生效）
func TestParsePattern_RangeReversed(t *testing.T) {
	const raw = "1.2.3.99-1.2.3.4"

	_, err := ParsePattern(raw)
	if err == nil {
		t.Fatal("ParsePattern 对颠倒区间应当报错")
	}
	if !errors.Is(err, ErrRangeReversed) {
		t.Fatalf("错误应当可被 errors.Is(ErrRangeReversed) 识别，实际: %v", err)
	}

	p, err := ParsePatternLenient(raw)
	if err != nil {
		t.Fatalf("ParsePatternLenient 应当自动交换后成功，实际: %v", err)
	}
	if p.Kind != KindRange {
		t.Fatalf("交换后应为区间，实际 kind=%d", p.Kind)
	}

	// MatchSet.Add 走宽容解析，颠倒的存量数据必须继续生效
	m := BuildMatchSet([]string{raw})
	if !m.Contains(net.ParseIP("1.2.3.50")) {
		t.Error("颠倒区间经自动交换后应当命中区间内地址")
	}
	if m.Contains(net.ParseIP("1.2.3.200")) {
		t.Error("颠倒区间不应命中区间外地址")
	}
}

// 连续掩码通配符与等价 CIDR 必须语义完全一致
func TestWildcardCIDREquivalence(t *testing.T) {
	pairs := []struct{ wildcard, cidr string }{
		{"10.*.*.*", "10.0.0.0/8"},
		{"10.10.*.*", "10.10.0.0/16"},
		{"192.168.1.*", "192.168.1.0/24"},
		{"2001:db8:*:*:*:*:*:*", "2001:db8::/32"},
	}
	rnd := rand.New(rand.NewSource(20260803))
	for _, pair := range pairs {
		mw := BuildMatchSet([]string{pair.wildcard})
		mc := BuildMatchSet([]string{pair.cidr})
		for i := 0; i < 200; i++ {
			var ip net.IP
			if strings.Contains(pair.cidr, ":") {
				b := make([]byte, 16)
				rnd.Read(b)
				if i%2 == 0 { // 一半构造成命中前缀
					b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
				}
				ip = net.IP(b)
			} else {
				b := make([]byte, 4)
				rnd.Read(b)
				if i%2 == 0 { // 一半构造成命中前缀
					switch pair.cidr {
					case "192.168.1.0/24":
						b[0], b[1], b[2] = 192, 168, 1
					case "10.10.0.0/16":
						b[0], b[1] = 10, 10
					default:
						b[0] = 10
					}
				}
				ip = net.IP(b)
			}
			if mw.Contains(ip) != mc.Contains(ip) {
				t.Fatalf("%s 与 %s 对 %s 判定不一致: %v vs %v",
					pair.wildcard, pair.cidr, ip, mw.Contains(ip), mc.Contains(ip))
			}
		}
	}
}

// 区间→CIDR 分解必须与朴素的字节比较判定逐地址一致，且条数在可证明上界内
func TestRangeToPrefixes_Exact(t *testing.T) {
	cases := []struct{ start, end string }{
		{"1.2.3.4", "1.2.3.99"},
		{"10.0.0.0", "10.0.1.255"},
		{"192.168.0.1", "192.168.0.1"},
		{"0.0.0.0", "255.255.255.255"},
		{"1.2.3.255", "1.2.4.0"},
	}
	for _, c := range cases {
		start := net.ParseIP(c.start).To4()
		end := net.ParseIP(c.end).To4()
		prefixes := rangeToPrefixes(start, end)
		if len(prefixes) == 0 {
			t.Fatalf("[%s,%s] 分解结果为空", c.start, c.end)
		}
		if len(prefixes) > 62 {
			t.Errorf("[%s,%s] 分解出 %d 条，超过 IPv4 上界 62", c.start, c.end, len(prefixes))
		}

		trie := newCIDRTrie()
		for _, pe := range prefixes {
			trie.insert(pe.Net, pe.Bits)
		}
		// 在区间内外各抽样验证；小区间直接全量枚举
		for i := 0; i < 3000; i++ {
			b := make([]byte, 4)
			rand.New(rand.NewSource(int64(i) * 7919)).Read(b)
			want := bytes.Compare(b, start) >= 0 && bytes.Compare(b, end) <= 0
			if got := trie.contains(b, 32); got != want {
				t.Fatalf("[%s,%s] 对 %v 判定错误: got=%v want=%v", c.start, c.end, net.IP(b), got, want)
			}
		}
		// 边界四点必须精确
		for _, probe := range []struct {
			ip   []byte
			want bool
		}{
			{start, true},
			{end, true},
			{decOne(start), false},
			{incOne(end), false},
		} {
			if probe.ip == nil {
				continue
			}
			if got := trie.contains(probe.ip, 32); got != probe.want {
				t.Errorf("[%s,%s] 边界 %v 判定错误: got=%v want=%v", c.start, c.end, net.IP(probe.ip), got, probe.want)
			}
		}
	}
}

func TestRangeToPrefixes_V6Bound(t *testing.T) {
	start := net.ParseIP("::1").To16()
	end := net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe").To16()
	prefixes := rangeToPrefixes(start, end)
	if len(prefixes) == 0 {
		t.Fatal("v6 极端区间分解结果为空")
	}
	if len(prefixes) > 254 {
		t.Errorf("v6 分解出 %d 条，超过上界 254", len(prefixes))
	}
	trie := newCIDRTrie()
	for _, pe := range prefixes {
		trie.insert(pe.Net, pe.Bits)
	}
	if !trie.contains(net.ParseIP("2001:db8::1").To16(), 128) {
		t.Error("区间内的 v6 地址应当命中")
	}
	if trie.contains(net.ParseIP("::").To16(), 128) {
		t.Error("区间外的 :: 不应命中")
	}
}

func TestPattern_Match_FamilyIsolation(t *testing.T) {
	p4, _ := ParsePattern("10.10.*.*")
	if p4.Match(net.ParseIP("2001:db8::1")) {
		t.Error("v4 通配符不应命中 v6 地址")
	}
	p6, _ := ParsePattern("2001:db8:*:*:*:*:*:*")
	if p6.Match(net.ParseIP("10.10.1.1")) {
		t.Error("v6 通配符不应命中 v4 地址")
	}
	if p4.Match(nil) {
		t.Error("nil ip 应当返回 false")
	}
}

// 「会匹配全部地址」的隐晦写法必须能被识别出来：
// 白名单误写成 *.*.*.* 等于全站不设防，黑名单误写成它等于封禁所有人。
func TestIsCatchAllWildcard(t *testing.T) {
	cases := map[string]bool{
		"*.*.*.*":                 true,
		"*:*:*:*:*:*:*:*":         true,
		"0.0.0.0-255.255.255.255": true, // 全空间区间，与全通配同等风险
		"::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff": true,
		"10.*.*.*":          false,
		"0.0.0.0/0":         false, // 显式 CIDR：用户明确表达了全匹配，不拦
		"::/0":              false,
		"1.2.3.4-1.2.3.99":  false,
		"0.0.0.0-0.0.0.255": false,
		"not-an-ip":         false,
		"10.10.*.*":         false,
	}
	for raw, want := range cases {
		if got := IsCatchAllWildcard(raw); got != want {
			t.Errorf("IsCatchAllWildcard(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestMatchPatternCached(t *testing.T) {
	cases := []struct {
		ip, pattern string
		want        bool
	}{
		{"1.2.3.4", "1.2.3.4", true},
		{"1.2.3.5", "1.2.3.4", false},
		{"10.0.5.9", "10.0.0.0/8", true},
		{"11.0.5.9", "10.0.0.0/8", false},
		{"10.10.7.7", "10.10.*.*", true},
		{"10.11.7.7", "10.10.*.*", false},
		{"10.5.1.9", "10.*.1.*", true},
		{"10.5.2.9", "10.*.1.*", false},
		{"1.2.3.50", "1.2.3.4-1.2.3.99", true},
		{"1.2.3.100", "1.2.3.4-1.2.3.99", false},
		{"2001:db8::1", "2001:db8:*:*:*:*:*:*", true},
		{"2001:db9::1", "2001:db8:*:*:*:*:*:*", false},
		{"1.2.3.4", "垃圾模式", false}, // 非法 pattern 恒 false
		{"垃圾IP", "1.2.3.4", false}, // 非法 ip 恒 false
	}
	for _, c := range cases {
		// 连续调两次，验证缓存路径与首次解析路径结果一致
		for i := 0; i < 2; i++ {
			if got := MatchPatternStrCached(c.ip, c.pattern); got != c.want {
				t.Errorf("MatchPatternStrCached(%q,%q) 第%d次 = %v, want %v", c.ip, c.pattern, i+1, got, c.want)
			}
		}
	}
}

func decOne(b []byte) []byte {
	out := append([]byte(nil), b...)
	for i := len(out) - 1; i >= 0; i-- {
		if out[i] > 0 {
			out[i]--
			return out
		}
		out[i] = 0xff
	}
	return nil // 全 0，无前驱
}

func incOne(b []byte) []byte {
	out := append([]byte(nil), b...)
	for i := len(out) - 1; i >= 0; i-- {
		if out[i] < 0xff {
			out[i]++
			return out
		}
		out[i] = 0
	}
	return nil // 全 F，无后继
}
