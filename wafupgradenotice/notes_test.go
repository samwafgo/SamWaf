package wafupgradenotice

import (
	"os"
	"strings"
	"testing"
)

// TestNotesYAML 构建期校验内置清单：任何一条不合规都不许发出去。
//
// 这是本功能唯一的把关点——清单在运行期是"跳过非法条目"的容错策略，
// 真出了问题界面上只会少一条，不会报错，所以必须在这里拦住。
func TestNotesYAML(t *testing.T) {
	notes, err := ParseAll()
	if err != nil {
		t.Fatalf("解析 upgrade_notes.yaml 失败: %v", err)
	}
	if len(notes) == 0 {
		t.Fatal("内置清单为空")
	}

	seen := make(map[string]bool, len(notes))
	for _, n := range notes {
		if err := ValidateNote(n); err != nil {
			t.Errorf("清单条目不合规: %v", err)
			continue
		}
		if seen[n.Id] {
			t.Errorf("条目 id 重复: %s（id 是幂等键，必须全局唯一）", n.Id)
		}
		seen[n.Id] = true
	}
}

// TestNotesTextNotIdentical 中英文案必须真的是两套，不能把中文原样复制到 en。
func TestNotesTextNotIdentical(t *testing.T) {
	notes, err := ParseAll()
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	for _, n := range notes {
		if n.ZH.Title == n.EN.Title {
			t.Errorf("[%s] 中英标题完全相同，en 文案疑似没翻译", n.Id)
		}
		if n.ZH.Detail == n.EN.Detail {
			t.Errorf("[%s] 中英详情完全相同，en 文案疑似没翻译", n.Id)
		}
	}
}

// TestConfigSetItemExists 一键应用(v2)引用的配置项必须真实存在。
//
// 配置项在 waftask/task_config.go 里注册，这里直接扫源码做交叉比对：
// 清单里写错一个 item 名，v2 上线时就是"点了没反应"，而且只有用户会发现。
func TestConfigSetItemExists(t *testing.T) {
	notes, err := ParseAll()
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	var wanted []string
	for _, n := range notes {
		if n.Apply.Type == ApplyConfigSet && n.Apply.Item != "" {
			wanted = append(wanted, n.Apply.Item)
		}
	}
	if len(wanted) == 0 {
		t.Skip("清单里暂无 config_set 条目")
	}
	src, err := os.ReadFile("../waftask/task_config.go")
	if err != nil {
		t.Fatalf("读取 task_config.go 失败: %v", err)
	}
	text := string(src)
	for _, item := range wanted {
		if !strings.Contains(text, `"`+item+`"`) {
			t.Errorf("配置项 %q 在 waftask/task_config.go 里没有注册", item)
		}
	}
}

// TestValidateNoteRejectsBadInput 逐项验证校验规则本身没写漏。
func TestValidateNoteRejectsBadInput(t *testing.T) {
	good := Note{
		Id:      "sample_note",
		Version: "v1.3.24",
		Kind:    KindAction,
		Level:   LevelNormal,
		Page:    "/sys/SystemConfig",
		Doc:     "https://doc.samwaf.com/x.html",
		Apply:   Apply{Type: ApplyNavigate},
		ZH:      Text{Title: "标题", Detail: "详情", EffectOn: "开了会怎样", EffectOff: "不开的代价", Revert: "怎么撤"},
		EN:      Text{Title: "Title", Detail: "Detail", EffectOn: "on", EffectOff: "off", Revert: "revert"},
	}
	if err := ValidateNote(good); err != nil {
		t.Fatalf("合法条目被判为不合法: %v", err)
	}

	cases := []struct {
		name  string
		mutit func(n *Note)
	}{
		{"id 含大写", func(n *Note) { n.Id = "BadId" }},
		{"version 非 semver", func(n *Note) { n.Version = "1.3.24" }},
		{"kind 非法", func(n *Note) { n.Kind = "whatever" }},
		{"level 非法", func(n *Note) { n.Level = "urgent" }},
		{"apply.type 非法", func(n *Note) { n.Apply = Apply{Type: "exec"} }},
		{"config_set 缺 item", func(n *Note) { n.Apply = Apply{Type: ApplyConfigSet, Value: "1"} }},
		{"navigate 带 item", func(n *Note) { n.Apply = Apply{Type: ApplyNavigate, Item: "x", Value: "1"} }},
		{"navigate 缺 page", func(n *Note) { n.Page = "" }},
		{"page 是外链", func(n *Note) { n.Page = "https://evil.example.com" }},
		{"doc 不是官方站", func(n *Note) { n.Doc = "https://evil.example.com/a" }},
		{"action 缺 effect_off", func(n *Note) { n.ZH.EffectOff = "" }},
		{"action 缺 revert(英文)", func(n *Note) { n.EN.Revert = "" }},
		{"英文标题为空", func(n *Note) { n.EN.Title = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := good
			c.mutit(&n)
			if err := ValidateNote(n); err == nil {
				t.Errorf("期望校验失败，实际通过了")
			}
		})
	}
}
