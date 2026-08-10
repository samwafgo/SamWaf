package waf_service

import (
	"SamWaf/model"
	"testing"
)

// 落地态判定用例。
//
// 钉死的是本模块最容易踩错、且踩错后会「沉默失效」的那条链路：
// 快照先落库 → 系统层落地中断(只封了一半) → 下次同步拉到相同内容 →
// 若只看内容 sha 就会判定"无变化"早退 → **永远不再落地**，页面却一直显示 ok。
// 只要有人把 landingUpToDate 退化回"只比内容 sha"，下面第 3 条就会失败。

func TestLandingUpToDate(t *testing.T) {
	const shaA = "aaaa1111"
	const shaB = "bbbb2222"

	cases := []struct {
		name        string
		contentSha  string // 本次拉取解析出来的内容 sha
		snapshotSha string // 库里快照的 sha
		landedSha   string // 已确认落地的 sha
		want        bool   // 是否可以完全跳过落地
		why         string
	}{
		{
			name:       "内容没变且已落地-可跳过",
			contentSha: shaA, snapshotSha: shaA, landedSha: shaA,
			want: true, why: "正常稳态，每天同步都走这条，不该做任何防火墙操作",
		},
		{
			name:       "内容变了-必须落地",
			contentSha: shaB, snapshotSha: shaA, landedSha: shaA,
			want: false, why: "源方更新了名单",
		},
		{
			name:       "内容没变但落地态是旧的-必须落地",
			contentSha: shaA, snapshotSha: shaA, landedSha: shaB,
			want: false, why: "上次落地中断，防火墙里还是旧快照——这条是本次修复的核心",
		},
		{
			name:       "内容没变但从未确认落地-必须落地",
			contentSha: shaA, snapshotSha: shaA, landedSha: "",
			want: false, why: "老版本升级上来 landed_sha 为空，要做一次覆盖式重建把残留修正",
		},
		{
			name:       "首次同步-必须落地",
			contentSha: shaA, snapshotSha: "", landedSha: "",
			want: false, why: "还没有快照",
		},
		{
			name:       "快照为空但落地态莫名等于内容-仍必须落地",
			contentSha: shaA, snapshotSha: "", landedSha: shaA,
			want: false, why: "快照都没有，落地态不可信，不能据此跳过",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := landingUpToDate(c.contentSha, c.snapshotSha, c.landedSha); got != c.want {
				t.Errorf("landingUpToDate(%q,%q,%q) = %v, want %v —— %s",
					c.contentSha, c.snapshotSha, c.landedSha, got, c.want, c.why)
			}
		})
	}
}

func TestSameContent(t *testing.T) {
	if !sameContent("a", "a") {
		t.Error("相同 sha 应判定为内容未变")
	}
	if sameContent("a", "b") {
		t.Error("不同 sha 应判定为内容已变")
	}
	if sameContent("", "") {
		t.Error("快照 sha 为空表示从没存过快照，必须按内容已变处理，否则首次同步会被跳过")
	}
	if sameContent("a", "") {
		t.Error("快照 sha 为空时不能判定为内容未变")
	}
}

// TestLandedOK 列表页「未完全落地」提示的判据。
// 宁可漏报也不能误报：给用户报一个不成立的警，比不报更糟。
func TestLandedOK(t *testing.T) {
	const shaA = "aaaa1111"
	const shaB = "bbbb2222"
	ch := func(land, landedSha string) model.ThreatIPChannel {
		return model.ThreatIPChannel{LandTarget: land, LandedSha: landedSha}
	}

	cases := []struct {
		name        string
		ch          model.ThreatIPChannel
		snapshotSha string
		want        bool
		why         string
	}{
		{"系统层已落地", ch(model.ThreatLandSystem, shaA), shaA, true, "正常稳态"},
		{"两者已落地", ch(model.ThreatLandBoth, shaA), shaA, true, "正常稳态"},
		{"系统层落地态是旧的", ch(model.ThreatLandSystem, shaB), shaA, false, "上次落地中断，该提示用户"},
		{"系统层从未确认落地", ch(model.ThreatLandSystem, ""), shaA, false, "老库升级上来，对账会在一小时内补上"},
		{"仅WAF层-不该报警", ch(model.ThreatLandWAF, ""), shaA, true, "本来就不往系统防火墙写"},
		{"还没有快照-不该报警", ch(model.ThreatLandSystem, ""), "", true, "从没同步过，没什么可落地的"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := landedOK(c.ch, c.snapshotSha); got != c.want {
				t.Errorf("landedOK(land=%s, landedSha=%q, snapshotSha=%q) = %v, want %v —— %s",
					c.ch.LandTarget, c.ch.LandedSha, c.snapshotSha, got, c.want, c.why)
			}
		})
	}
}

func TestShortSha(t *testing.T) {
	if got := shortSha(""); got != "(空)" {
		t.Errorf("空 sha 应显示为 (空)，got %q", got)
	}
	if got := shortSha("0123456789abcdef"); got != "01234567" {
		t.Errorf("长 sha 应截断到 8 位，got %q", got)
	}
	if got := shortSha("abc"); got != "abc" {
		t.Errorf("短 sha 应原样返回，got %q", got)
	}
}
