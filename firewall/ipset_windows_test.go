//go:build windows

package firewall

import (
	"fmt"
	"strings"
	"testing"
)

// TestExtractShardRuleNames 覆盖"从 netsh 原始输出里挑分片规则名"的解析。
// 这段解析是清理逻辑的地基：漏挑 → 残留规则删不掉、下次重建叠成重复；
// 多挑 → 误删别的集合甚至别的功能的规则。
func TestExtractShardRuleNames(t *testing.T) {
	// 模拟简体中文 Windows 的 netsh 输出(GBK 字节)，规则名本身是 ASCII。
	// 用原始字节是刻意的：解析不该依赖任何编码/本地化标签。
	gbkLabel := []byte{0xB9, 0xE6, 0xD4, 0xF2, 0xC3, 0xFB, 0xB3, 0xC6} // "规则名称"
	var buf []byte
	appendRule := func(name string) {
		buf = append(buf, gbkLabel...)
		buf = append(buf, []byte(":                             "+name+"\r\n")...)
		buf = append(buf, []byte(strings.Repeat("-", 70)+"\r\n")...)
	}

	appendRule("SamWAF_Set_samwaf_sub_ustc_0")
	appendRule("SamWAF_Set_samwaf_sub_ustc_61")
	appendRule("SamWAF_Set_samwaf_sub_ustc_61") // 重复副本：应去重成一个名字
	appendRule("SamWAF_Set_samwaf_sub_ustc_7")
	appendRule("SamWAF_Set_samwaf_sub_ustc2_3")  // 别的集合(前缀相似)：不能误挑
	appendRule("SamWAF_Set_samwaf_sub_ustc_x_1") // 别的集合(本集合名+后缀)：不能误挑
	appendRule("SamWAF_Set_samwaf_sub_ipsum_5")  // 别的渠道：不能误挑
	appendRule("SamWAF_Block_1_2_3_4")           // 逐条封禁规则：不能误挑
	appendRule("SamWAF_Set_samwaf_sub_ustc_abc") // 后缀不是纯数字：不是分片名
	appendRule("SamWAF_Set_samwaf_hostguard_2")  // 主机防爆破集合：不能误挑

	got := extractShardRuleNames(buf, "samwaf_sub_ustc")
	want := []string{
		"SamWAF_Set_samwaf_sub_ustc_0",
		"SamWAF_Set_samwaf_sub_ustc_61",
		"SamWAF_Set_samwaf_sub_ustc_7",
	}
	if len(got) != len(want) {
		t.Fatalf("挑出的分片规则名数量不对: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 个不匹配: got %q, want %q (完整: %v)", i, got[i], want[i], got)
		}
	}
}

// TestExtractShardRuleNamesEmpty 没有任何本集合规则时应返回空，避免误删
func TestExtractShardRuleNamesEmpty(t *testing.T) {
	out := []byte("Rule Name:  SamWAF_Set_samwaf_sub_ipsum_1\r\nRule Name:  Some Other Rule\r\n")
	if got := extractShardRuleNames(out, "samwaf_sub_ustc"); len(got) != 0 {
		t.Fatalf("不该挑出任何规则名, got %v", got)
	}
}

// TestExtractShardRuleNamesEnglishOutput 英文 Windows 的输出同样要能挑出来
func TestExtractShardRuleNamesEnglishOutput(t *testing.T) {
	out := []byte("Rule Name:                            SamWAF_Set_samwaf_hostguard_0\r\n" +
		"----------------------------------------------------------------------\r\n" +
		"Enabled:                              Yes\r\n")
	got := extractShardRuleNames(out, "samwaf_hostguard")
	if len(got) != 1 || got[0] != "SamWAF_Set_samwaf_hostguard_0" {
		t.Fatalf("英文输出解析失败, got %v", got)
	}
}

// TestIsShardRuleName 前缀/纯数字后缀的边界
func TestIsShardRuleName(t *testing.T) {
	cases := []struct {
		name    string
		setName string
		want    bool
	}{
		{"SamWAF_Set_samwaf_sub_ustc_0", "samwaf_sub_ustc", true},
		{"SamWAF_Set_samwaf_sub_ustc_1234", "samwaf_sub_ustc", true},
		{"SamWAF_Set_samwaf_sub_ustc_", "samwaf_sub_ustc", false},    // 没有序号
		{"SamWAF_Set_samwaf_sub_ustc_1a", "samwaf_sub_ustc", false},  // 序号不纯数字
		{"SamWAF_Set_samwaf_sub_ustc2_1", "samwaf_sub_ustc", false},  // 别的集合
		{"SamWAF_Set_samwaf_sub_ustc_x_1", "samwaf_sub_ustc", false}, // 别的集合
		{"SamWAF_Block_1_2_3_4", "samwaf_sub_ustc", false},           // 逐条封禁规则
		{"", "samwaf_sub_ustc", false},
	}
	for _, c := range cases {
		if got := isShardRuleName(c.name, c.setName); got != c.want {
			t.Errorf("isShardRuleName(%q, %q) = %v, want %v", c.name, c.setName, got, c.want)
		}
	}
}

// TestParseIpsetEntryCount 解析 `ipset list -t` 头部的条目数。
// 落地对账靠它判断"系统里到底灌了多少条"，解析不出必须返回 ok=false（按需要重建处理），
// 绝不能默认成 0 —— 那会让"空集合"和"解析失败"无法区分。
func TestParseIpsetEntryCount(t *testing.T) {
	terse := "Name: samwaf_sub_ustc\n" +
		"Type: hash:net\n" +
		"Revision: 6\n" +
		"Header: family inet hashsize 1024 maxelem 2097152\n" +
		"Size in memory: 852416\n" +
		"References: 1\n" +
		"Number of entries: 13157\n"
	if n, ok := parseIpsetEntryCount(terse); !ok || n != 13157 {
		t.Fatalf("正常输出解析失败: n=%d ok=%v", n, ok)
	}

	if n, ok := parseIpsetEntryCount("Name: x\nNumber of entries: 0\n"); !ok || n != 0 {
		t.Fatalf("空集合应解析出 0 且 ok=true: n=%d ok=%v", n, ok)
	}

	// 集合不存在时 ipset 的报错里没有这一行
	if _, ok := parseIpsetEntryCount("ipset v7.15: The set with the given name does not exist"); ok {
		t.Fatal("集合不存在时必须 ok=false，否则会被当成 0 条而误判为一致")
	}
	if _, ok := parseIpsetEntryCount(""); ok {
		t.Fatal("空输出必须 ok=false")
	}
	if _, ok := parseIpsetEntryCount("Number of entries: abc"); ok {
		t.Fatal("数字解析不出时必须 ok=false")
	}
}

// TestShardIPsByLenRoundTrip 分片不丢条目、单片不超长——分片错了会直接导致封禁范围出错
func TestShardIPsByLenRoundTrip(t *testing.T) {
	ips := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		ips = append(ips, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	shards := shardIPsByLen(ips, maxRemoteIPChars)
	if len(shards) == 0 {
		t.Fatal("没有分出任何分片")
	}
	total := 0
	for i, s := range shards {
		if len(s) > maxRemoteIPChars {
			t.Fatalf("第 %d 个分片超长: %d > %d", i, len(s), maxRemoteIPChars)
		}
		total += len(strings.Split(s, ","))
	}
	if total != len(ips) {
		t.Fatalf("分片后条目数对不上: got %d, want %d", total, len(ips))
	}
}
