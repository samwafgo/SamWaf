package waf_service

import (
	"SamWaf/wafenginecore/ipset"
	"SamWaf/waftask/threatip"
	"testing"
)

// buildSet 用一组原文构造排除集，绕开数据库(单测不依赖 DB)
func buildSet(t *testing.T, raws ...string) *ExcludeSet {
	t.Helper()
	entries := make([]excludeEntry, 0, len(raws))
	for _, raw := range raws {
		pat, err := ipset.ParsePatternLenient(raw)
		if err != nil {
			t.Fatalf("排除条目 %q 解析失败: %v", raw, err)
		}
		entries = append(entries, excludeEntry{
			Raw: raw, pat: pat,
			exact: pat.Prefix >= 0 && len(pat.Mask) == pat.Width,
		})
	}
	return &ExcludeSet{entries: entries, fast: ipset.BuildMatchSet(raws)}
}

// TestEntryCoversDirection 钉死方向性：只有"大的能排掉小的"，反过来不行。
// 这是用户最容易踩的坑——排除 1.2.3.4 却指望剔掉快照里的 1.2.3.0/24。
func TestEntryCoversDirection(t *testing.T) {
	cases := []struct {
		exclude  string
		snapshot string
		want     bool
		why      string
	}{
		{"1.2.3.4", "1.2.3.4", true, "完全相等"},
		{"1.2.3.0/24", "1.2.3.4", true, "单IP落在排除段内"},
		{"1.2.3.0/24", "1.2.3.0/24", true, "网段相等"},
		{"1.2.0.0/16", "1.2.3.0/24", true, "大段包含小段"},
		{"1.2.3.4", "1.2.3.0/24", false, "小的排不掉大的——必须为 false"},
		{"1.2.3.0/24", "1.2.4.0/24", false, "相邻但不包含"},
		{"1.2.3.0/25", "1.2.3.0/24", false, "排除段比快照段小"},
		{"10.0.0.0/8", "10.1.2.3", true, "内网大段"},
		{"2001:db8::/32", "2001:db8::1", true, "IPv6 段含单地址"},
		{"1.2.3.0/24", "2001:db8::1", false, "协议族不同"},
	}
	for _, c := range cases {
		set := buildSet(t, c.exclude)
		got := set.matchEntry(c.snapshot) != nil
		if got != c.want {
			t.Errorf("排除 %q 对快照 %q：期望 %v 实际 %v（%s）", c.exclude, c.snapshot, c.want, got, c.why)
		}
	}
}

// TestFilterKeepsOrderAndCounts 过滤后仍是有序去重的列表，且条数统计准确
func TestFilterKeepsOrderAndCounts(t *testing.T) {
	snapshot := []string{"1.2.3.4", "1.2.3.5", "5.6.7.0/24", "9.9.9.9"}
	set := buildSet(t, "1.2.3.0/24")

	res := set.Filter(snapshot)
	if res.Excluded != 2 {
		t.Fatalf("期望剔除 2 条，实际 %d", res.Excluded)
	}
	want := []string{"5.6.7.0/24", "9.9.9.9"}
	if len(res.Effective) != len(want) {
		t.Fatalf("有效集条数不符：期望 %d 实际 %d (%v)", len(want), len(res.Effective), res.Effective)
	}
	for i := range want {
		if res.Effective[i] != want[i] {
			t.Errorf("有效集第 %d 条：期望 %q 实际 %q", i, want[i], res.Effective[i])
		}
	}
}

// TestEmptyExcludeIsIdentity 排除集为空时必须是恒等变换。
//
// 这条是升级平滑性的地基：effSha == contentSha 时，存量 landed_sha 全部保持有效，
// 升级后不会触发一次全量重建(Windows 上那是几十次 netsh × 每个渠道)。
func TestEmptyExcludeIsIdentity(t *testing.T) {
	snapshot := []string{"1.2.3.4", "5.6.7.0/24"}
	var empty *ExcludeSet // nil 也必须安全

	for name, set := range map[string]*ExcludeSet{"nil": empty, "空集": {}} {
		res := set.Filter(snapshot)
		if res.Excluded != 0 {
			t.Errorf("%s：不应剔除任何条目，实际剔了 %d", name, res.Excluded)
		}
		if threatip.ShaOf(res.Effective) != threatip.ShaOf(snapshot) {
			t.Errorf("%s：有效集 sha 必须等于内容 sha", name)
		}
	}
}

// TestShaOfMatchesEncodeSnapshot effSha 与 contentSha 必须同算法，否则两者无法比较，
// "内容没变且落地态一致就跳过"这个判据会永远不成立、每次同步都重建。
func TestShaOfMatchesEncodeSnapshot(t *testing.T) {
	ips := []string{"5.6.7.0/24", "1.2.3.4", "1.2.3.4"} // 故意乱序 + 重复
	_, sha, count, err := threatip.EncodeSnapshot(ips)
	if err != nil {
		t.Fatalf("EncodeSnapshot 失败: %v", err)
	}
	if count != 2 {
		t.Fatalf("去重后应为 2 条，实际 %d", count)
	}
	if got := threatip.ShaOf(ips); got != sha {
		t.Errorf("ShaOf 与 EncodeSnapshot 的 sha 不一致：%s vs %s", got, sha)
	}
}

// TestExcludeChangesEffSha 排除名单一变 effSha 就必须变——
// "排除生效"整个靠这一点驱动，不需要额外的缓存失效机制。
func TestExcludeChangesEffSha(t *testing.T) {
	snapshot := []string{"1.2.3.4", "5.6.7.8"}
	before := threatip.ShaOf(buildSet(t).Filter(snapshot).Effective)
	after := threatip.ShaOf(buildSet(t, "1.2.3.4").Filter(snapshot).Effective)
	if before == after {
		t.Error("加了排除条目后 effSha 必须变化，否则对账不会重建、排除永远不生效")
	}
}

// TestMatchedEntryForLookup 归属查询要能回答"这个 IP 为什么没被拦"。
//
// 同时钉死噪音边界：环境类自动来源(内网段/本机网卡/回环)虽然参与过滤，
// 但不该在归属查询里报出来——否则查任何一个内网地址都会显示"已被排除名单豁免"，
// 用户会误以为自己排除过它。
func TestMatchedEntryForLookup(t *testing.T) {
	set := buildSet(t, "1.2.3.0/24")
	set.entries[0].Id = "row-1" // 模拟落库条目

	if hit := set.MatchedEntry(mustIP(t, "1.2.3.99")); hit == nil || hit.Raw != "1.2.3.0/24" {
		t.Errorf("段内地址应报告命中 1.2.3.0/24，实际 %+v", hit)
	}
	if hit := set.MatchedEntry(mustIP(t, "9.9.9.9")); hit != nil {
		t.Errorf("段外地址不应命中，实际 %+v", hit)
	}

	ambient := buildSet(t, "10.0.0.0/8") // Id 为空 = 环境类自动来源
	if hit := ambient.MatchedEntry(mustIP(t, "10.1.2.3")); hit != nil {
		t.Errorf("环境类自动来源不该在归属查询里报出来，实际 %+v", hit)
	}
	// 但它仍然必须参与过滤——只是不报，不是不生效
	if res := ambient.Filter([]string{"10.1.2.3"}); res.Excluded != 1 {
		t.Errorf("环境类来源必须照常参与过滤，期望剔除 1 条，实际 %d", res.Excluded)
	}
}

// TestValidateExcludeEntry 写入侧校验：巨型网段必须挡死，
// 排除一个 /0 等于把整个威胁情报功能悄悄关掉。
func TestValidateExcludeEntry(t *testing.T) {
	bad := []string{"", "0.0.0.0/0", "::/0", "1.0.0.0/4", "10.10.*.*", "1.2.3.4-1.2.3.9", "not-an-ip",
		"2001:db8::/16"}
	for _, v := range bad {
		if err := ValidateExcludeEntry(v); err == nil {
			t.Errorf("%q 应当被拒绝", v)
		}
	}
	good := []string{"1.2.3.4", "1.2.3.0/24", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32"}
	for _, v := range good {
		if err := ValidateExcludeEntry(v); err != nil {
			t.Errorf("%q 应当通过，实际被拒: %v", v, err)
		}
	}
}

// TestCoveringEntryIn 排除没生效时，要能指出"你其实该排这个段"
func TestCoveringEntryIn(t *testing.T) {
	snapshot := []string{"1.2.3.0/24", "9.9.9.9"}
	pat, err := ipset.ParsePattern("1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if got := coveringEntryIn(snapshot, pat); got != "1.2.3.0/24" {
		t.Errorf("应提示所属网段 1.2.3.0/24，实际 %q", got)
	}
	pat2, _ := ipset.ParsePattern("8.8.8.8")
	if got := coveringEntryIn(snapshot, pat2); got != "" {
		t.Errorf("不属于任何网段时应返回空，实际 %q", got)
	}
}

func mustIP(t *testing.T, s string) []byte {
	t.Helper()
	p, err := ipset.ParsePattern(s)
	if err != nil {
		t.Fatalf("解析 %q 失败: %v", s, err)
	}
	return p.Value
}
