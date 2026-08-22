package wafupgradenotice

import (
	"sort"
	"strings"
	"testing"
)

func fixture() []Note {
	return []Note{
		{Id: "fresh_a", Version: "v1.3.20", FreshInstall: true},
		{Id: "fresh_b", Version: "v1.3.21", FreshInstall: true},
		{Id: "n_21", Version: "v1.3.21"},
		{Id: "n_22", Version: "v1.3.22"},
		{Id: "n_23", Version: "v1.3.23"},
		{Id: "n_24", Version: "v1.3.24"},
	}
}

func ids(notes []Note) string {
	out := make([]string, 0, len(notes))
	for _, n := range notes {
		out = append(out, n.Id)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestSelectFrom(t *testing.T) {
	cases := []struct {
		name         string
		last         string
		current      string
		freshInstall bool
		want         string
	}{
		{"升级跨两个版本", "v1.3.21", "v1.3.23", false, "n_22,n_23"},
		{"升级一个版本", "v1.3.22", "v1.3.23", false, "n_23"},
		{"同版本重启不生成", "v1.3.23", "v1.3.23", false, ""},
		{"降级不生成", "v1.3.24", "v1.3.22", false, ""},
		{"全新安装只给新手清单", "", "v1.3.23", true, "fresh_a,fresh_b"},
		{"老库无版本记录只给当前版本条目", "", "v1.3.23", false, "n_23"},
		{"老库无版本记录且当前版本无条目", "", "v1.3.99", false, ""},
		{"当前版本非法", "v1.3.21", "dev", false, ""},
		{"上次版本非法当作无区间", "garbage", "v1.3.23", false, ""},
		{"区间上界闭合", "v1.3.23", "v1.3.24", false, "n_24"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ids(selectFrom(fixture(), c.last, c.current, c.freshInstall))
			if got != c.want {
				t.Errorf("last=%q current=%q fresh=%v\n got: %q\nwant: %q", c.last, c.current, c.freshInstall, got, c.want)
			}
		})
	}
}

// TestSelectFromExcludesFreshOnUpgrade 升级路径下绝不能混进"全新安装建议"，
// 否则老用户升个级就会被要求"立即修改初始口令"。
func TestSelectFromExcludesFreshOnUpgrade(t *testing.T) {
	for _, n := range selectFrom(fixture(), "v1.3.19", "v1.3.24", false) {
		if n.FreshInstall {
			t.Errorf("升级路径混入了全新安装条目: %s", n.Id)
		}
	}
}

// TestNoteTextLang 语言回落：非 en 一律给中文
func TestNoteTextLang(t *testing.T) {
	n := Note{
		ZH: Text{Title: "中文"},
		EN: Text{Title: "English"},
	}
	if got := n.Text("en_US").Title; got != "English" {
		t.Errorf("en_US 应取英文，实际 %q", got)
	}
	if got := n.Text("zh_CN").Title; got != "中文" {
		t.Errorf("zh_CN 应取中文，实际 %q", got)
	}
	if got := n.Text("").Title; got != "中文" {
		t.Errorf("空语言应回落中文，实际 %q", got)
	}
}

// TestAllSkipsInvalid 运行期加载必须只吐合法条目
func TestAllSkipsInvalid(t *testing.T) {
	if err := LoadError(); err != nil {
		t.Fatalf("内置清单加载失败: %v", err)
	}
	for _, n := range All() {
		if err := ValidateNote(n); err != nil {
			t.Errorf("All() 返回了不合法条目: %v", err)
		}
	}
}

// TestDisplayVersion 展示层砍掉 -beta.x 后缀：存精确值、显示干净值
func TestDisplayVersion(t *testing.T) {
	cases := map[string]string{
		"v1.3.24-beta.15": "v1.3.24",
		"v1.3.24":         "v1.3.24",
		"v1.3.24-rc.1":    "v1.3.24",
		"v1.3":            "v1.3.0", // Canonical 会补齐 patch 位
		"garbage":         "garbage",
		"":                "",
	}
	for in, want := range cases {
		if got := DisplayVersion(in); got != want {
			t.Errorf("DisplayVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRawVersionsFor 下拉里选的展示版本要能还原回清单里的原始版本号，
// 否则库里存着 v1.3.24-beta.15、前端传 v1.3.24，过滤永远查不到东西。
func TestRawVersionsFor(t *testing.T) {
	if got := RawVersionsFor(""); got != nil {
		t.Errorf("空版本应返回 nil，实际 %v", got)
	}
	// 清单里没有的版本原样返回，让查询自然落空而不是退化成"不过滤"
	got := RawVersionsFor("v9.9.9")
	if len(got) != 1 || got[0] != "v9.9.9" {
		t.Errorf("未知版本应原样返回，实际 %v", got)
	}
	// 内置清单里的真实版本必须能被自己的展示值还原
	for _, n := range All() {
		display := DisplayVersion(n.Version)
		found := false
		for _, raw := range RawVersionsFor(display) {
			if raw == n.Version {
				found = true
			}
		}
		if !found {
			t.Errorf("%s(%s) 的展示版本 %s 还原不回原始版本", n.Id, n.Version, display)
		}
	}
}
