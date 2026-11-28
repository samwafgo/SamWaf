package ipset

import (
	"net"
	"strings"
	"testing"
)

func TestThreatIndexMatchWAFAndChannelOrder(t *testing.T) {
	t.Cleanup(func() { SetGlobalThreatIndex(nil) })

	chSystem := ThreatChannelMatcher{
		Code:       "a_sys",
		Name:       "System Only Feed",
		LandTarget: "system",
		Set:        BuildMatchSet([]string{"198.51.100.10"}),
	}
	chFirehol := ThreatChannelMatcher{
		Code:       "firehol_l1",
		Name:       "FireHOL Level1",
		LandTarget: "both",
		Set:        BuildMatchSet([]string{"203.0.113.0/24"}),
	}
	chIpsum := ThreatChannelMatcher{
		Code:       "ipsum",
		Name:       "IPsum",
		LandTarget: "waf",
		Set:        BuildMatchSet([]string{"203.0.113.5", "192.0.2.9"}),
	}

	idx := &ThreatIndex{
		WAFUnion: BuildMatchSet([]string{"203.0.113.0/24", "192.0.2.9"}),
		Channels: []ThreatChannelMatcher{chSystem, chFirehol, chIpsum},
	}
	SetGlobalThreatIndex(idx)

	// 1. 仅 system 层 IP 绝不被 WAF 层拦截
	if matched, _ := GetGlobalThreatIndex().MatchWAF(net.ParseIP("198.51.100.10")); matched {
		t.Fatal("仅 system 落地层的渠道不应在 WAF 应用层触发拦截")
	}

	// 2. 同时命中多渠道时，返回全部命中渠道，FormatThreatIPRule 取首命中（按 Code 升序）
	matched, hits := GetGlobalThreatIndex().MatchWAF(net.ParseIP("203.0.113.5"))
	if !matched || len(hits) != 2 {
		t.Fatalf("期望命中 2 个 WAF 渠道，实际 matched=%v hits=%+v", matched, hits)
	}
	if got := FormatThreatIPRule(hits); got != "威胁情报IP:FireHOL Level1" {
		t.Fatalf("期望首命中渠道名，实际 %q", got)
	}

	// 3. 命中单渠道
	matched, hits = GetGlobalThreatIndex().MatchWAF(net.ParseIP("192.0.2.9"))
	if !matched || FormatThreatIPRule(hits) != "威胁情报IP:IPsum" {
		t.Fatalf("期望 威胁情报IP:IPsum，实际 matched=%v rule=%q", matched, FormatThreatIPRule(hits))
	}

	// 4. 简化 SetGlobalThreatMatcher 兼容兜底
	SetGlobalThreatMatcher(BuildMatchSet([]string{"198.51.100.99"}))
	matched, hits = GetGlobalThreatIndex().MatchWAF(net.ParseIP("198.51.100.99"))
	if !matched || FormatThreatIPRule(hits) != ThreatIPRulePrefix {
		t.Fatalf("无渠道元数据时应回退为 %q，实际 matched=%v rule=%q", ThreatIPRulePrefix, matched, FormatThreatIPRule(hits))
	}
}

func TestFormatThreatIPRuleSanitize(t *testing.T) {
	// 含逗号、引号、分号、SQL注释符、控制字符的名称应被清洗干净
	got := FormatThreatIPRule([]ThreatChannelMatcher{{
		Code: "bad_ch",
		Name: "  Bad,Feed'\"`;\\--/*#*/\nName  ",
	}})
	if got != "威胁情报IP:BadFeedName" {
		t.Fatalf("危险字符未清洗干净，实际 %q", got)
	}
	if strings.ContainsAny(got, ",，'\"`;\\#\n\r") {
		t.Fatalf("输出仍含非法字符: %q", got)
	}

	// 名称清洗后为空时回退短码 Code
	got = FormatThreatIPRule([]ThreatChannelMatcher{{
		Code: "ustc_feed",
		Name: ",,,\"\"--",
	}})
	if got != "威胁情报IP:ustc_feed" {
		t.Fatalf("空名称应回退 Code，实际 %q", got)
	}

	// 超长名称按 rune 截断，且不切坏 UTF-8 字符
	longName := strings.Repeat("威胁源", 30) // 90 runes
	got = FormatThreatIPRule([]ThreatChannelMatcher{{Code: "long", Name: longName}})
	suffix := strings.TrimPrefix(got, ThreatIPRulePrefix+":")
	if len([]rune(suffix)) != threatIPChannelMaxRunes {
		t.Fatalf("期望截断至 %d rune，实际 %d rune (%q)", threatIPChannelMaxRunes, len([]rune(suffix)), suffix)
	}
}
