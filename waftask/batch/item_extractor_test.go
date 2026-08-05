package batch

import "testing"

// 批量导入的 IP 提取：整行本身是合法 IP 模式时必须原样保留。
//
// TestIPExtractor_RangeNotTruncated 是 fail-before 用例：
// 修复前 ExtractItem 直接走正则，对 "1.2.3.4-1.2.3.99" 只截出 "1.2.3.4"，
// 而截出来的单 IP 恰好又能通过校验 —— 用户导入一个区间，库里静默变成一个 IP，
// 全程无任何报错。
func TestIPExtractor_RangeNotTruncated(t *testing.T) {
	e := &IPExtractor{}
	cases := []string{
		"1.2.3.4-1.2.3.99",
		"192.168.1.10-192.168.1.20",
		"2001:db8::1-2001:db8::ff",
	}
	for _, raw := range cases {
		if got := e.ExtractItem(raw); got != raw {
			t.Errorf("ExtractItem(%q) = %q，区间被截断了", raw, got)
		}
		if !e.ValidateItem(raw) {
			t.Errorf("ValidateItem(%q) = false，区间写法应当被接受", raw)
		}
	}
}

func TestIPExtractor_Wildcard(t *testing.T) {
	e := &IPExtractor{}
	cases := []string{"10.10.*.*", "10.*.1.*", "2001:db8:*:*:*:*:*:*"}
	for _, raw := range cases {
		if got := e.ExtractItem(raw); got != raw {
			t.Errorf("ExtractItem(%q) = %q，通配符被改写了", raw, got)
		}
		if !e.ValidateItem(raw) {
			t.Errorf("ValidateItem(%q) = false，通配符写法应当被接受", raw)
		}
	}
}

// 原有能力回归：单 IP / CIDR 不受影响，非法内容仍被拒
func TestIPExtractor_Regression(t *testing.T) {
	e := &IPExtractor{}
	for _, raw := range []string{"1.2.3.4", "10.0.0.0/8", "2001:db8:0:0:0:0:0:1"} {
		if got := e.ExtractItem(raw); got != raw {
			t.Errorf("ExtractItem(%q) = %q", raw, got)
		}
		if !e.ValidateItem(raw) {
			t.Errorf("ValidateItem(%q) 应为 true", raw)
		}
	}
	for _, raw := range []string{"", "not-an-ip-at-all", "10.1*.0.0"} {
		if e.ValidateItem(e.ExtractItem(raw)) {
			t.Errorf("非法内容 %q 不应通过校验", raw)
		}
	}
}

// IP组条目必须挡住全通配写法：组可能被白名单引用，
// 源里混进一条 *.*.*.* 就等于全站放行，而手工录入(validateGroupItemIP)本来就是拒绝的。
func TestIPGroupExtractor_RejectCatchAll(t *testing.T) {
	e := &IPGroupExtractor{}
	for _, raw := range []string{"*.*.*.*", "*", "*:*:*:*:*:*:*:*"} {
		if e.ValidateItem(e.ExtractItem(raw)) {
			t.Errorf("全通配写法 %q 不应进入IP组", raw)
		}
	}
	// 显式的 0.0.0.0/0 是用户明确表达的全匹配，与手工录入一致，允许
	for _, raw := range []string{"0.0.0.0/0", "1.2.3.4", "10.0.0.0/8", "10.10.*.*", "1.2.3.4-1.2.3.99"} {
		if !e.ValidateItem(e.ExtractItem(raw)) {
			t.Errorf("%q 应当被IP组接受", raw)
		}
	}
}

func TestGetExtractor_IPGroup(t *testing.T) {
	if _, ok := GetExtractor("ipgroup").(*IPGroupExtractor); !ok {
		t.Fatal("ipgroup 类型必须使用 IPGroupExtractor")
	}
}

// 带前后缀的日志行仍走正则抽取（这是原有能力，不能因为新增前置判断而丢掉）
func TestIPExtractor_FallbackRegex(t *testing.T) {
	e := &IPExtractor{}
	if got := e.ExtractItem("2026-08-03 attack from 1.2.3.4 blocked"); got != "1.2.3.4" {
		t.Errorf("带前后缀的行应当抽出 1.2.3.4，实际 %q", got)
	}
	if got := e.ExtractItem("bad guy 10.0.0.0/8 # 备注"); got != "10.0.0.0/8" {
		t.Errorf("带备注的网段行应当抽出 10.0.0.0/8，实际 %q", got)
	}
}
