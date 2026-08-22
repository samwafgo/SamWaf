// Package wafupgradenotice 提供「升级须知」的内置清单：解析、校验与按版本区间挑选。
//
// 清单随版本编译进二进制（见 upgrade_notes.yaml），不走网络：
// 内网/离线部署升完级同样能看到，也不新增任何对外请求。
// 本包是纯函数层，不碰数据库——落库与状态流转在 service/waf_service。
package wafupgradenotice

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"
)

//go:embed upgrade_notes.yaml
var notesYAML []byte

// 条目类型
const (
	KindNotice = "notice" // 知悉：行为变了，用户无需动作
	KindAction = "action" // 建议操作：建议开/关某个能力
	KindCheck  = "check"  // 场景确认：只有部分用户受影响，需自查
)

// 重要程度：只有 high 会在登录后弹一次窗
const (
	LevelHigh   = "high"
	LevelNormal = "normal"
	LevelLow    = "low"
)

// 执行方式
const (
	ApplyNone      = "none"       // 无可执行动作
	ApplyNavigate  = "navigate"   // 跳到对应页面由用户自己操作
	ApplyConfigSet = "config_set" // v2：一键写配置（前端只传 id，item/value 由后端从本清单取）
)

// docPrefix 文档链接只允许指向官方文档站，防止清单将来接云端补丁时被用作跳板
const docPrefix = "https://doc.samwaf.com/"

// idPattern 条目 id 只允许小写字母、数字与下划线
var idPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// Text 一条须知的单语言文案
type Text struct {
	Title     string `yaml:"title"`
	Detail    string `yaml:"detail"`
	EffectOn  string `yaml:"effect_on"`
	EffectOff string `yaml:"effect_off"`
	Revert    string `yaml:"revert"`
}

// Apply 建议操作的执行方式
type Apply struct {
	Type  string `yaml:"type"`
	Item  string `yaml:"item"`
	Value string `yaml:"value"`
}

// Note 内置清单里的一条须知
type Note struct {
	Id           string `yaml:"id"`            // 全局唯一，幂等键，一旦发布不得修改
	Version      string `yaml:"version"`       // 哪个版本引入（semver，参与区间计算）
	Kind         string `yaml:"kind"`          // notice / action / check
	Level        string `yaml:"level"`         // high / normal / low
	FreshInstall bool   `yaml:"fresh_install"` // true 表示这是"全新安装建议"，只在无历史版本时生成
	Page         string `yaml:"page"`          // 前端路由，「去设置」跳这里；只允许站内相对路径
	Doc          string `yaml:"doc"`           // 官方文档链接
	Apply        Apply  `yaml:"apply"`
	ZH           Text   `yaml:"zh"`
	EN           Text   `yaml:"en"`
}

// Text 按语言取文案，非 en 一律回落中文
func (n Note) Text(lang string) Text {
	if strings.HasPrefix(strings.ToLower(lang), "en") {
		return n.EN
	}
	return n.ZH
}

type noteFile struct {
	Notes []Note `yaml:"notes"`
}

var (
	loadOnce sync.Once
	loaded   []Note
	loadErr  error
)

// All 返回内置清单里全部**通过校验**的条目。
//
// 解析失败或个别条目非法时只跳过、不 panic：清单出问题绝不能拖垮启动。
// 真正的把关在 TestNotesYAML（构建期），发布前就会炸出来。
func All() []Note {
	loadOnce.Do(func() {
		var f noteFile
		if err := yaml.Unmarshal(notesYAML, &f); err != nil {
			loadErr = fmt.Errorf("解析内置升级须知清单失败: %w", err)
			return
		}
		seen := make(map[string]bool, len(f.Notes))
		for _, n := range f.Notes {
			if err := ValidateNote(n); err != nil {
				continue
			}
			if seen[n.Id] {
				continue
			}
			seen[n.Id] = true
			loaded = append(loaded, n)
		}
	})
	return loaded
}

// ParseAll 原样解析内置清单，不做任何过滤。
// 只给构建期单测用：它要看到全部条目（含非法的）才能把问题炸出来。
func ParseAll() ([]Note, error) {
	var f noteFile
	if err := yaml.Unmarshal(notesYAML, &f); err != nil {
		return nil, err
	}
	return f.Notes, nil
}

// LoadError 返回清单解析错误（仅供启动日志与单测使用）
func LoadError() error {
	All()
	return loadErr
}

// ByID 按 id 取条目
func ByID(id string) (Note, bool) {
	for _, n := range All() {
		if n.Id == id {
			return n, true
		}
	}
	return Note{}, false
}

// ValidateNote 校验单条须知。构建期单测对全量清单逐条调用，任何一条不过即发布不了。
func ValidateNote(n Note) error {
	if !idPattern.MatchString(n.Id) {
		return fmt.Errorf("id %q 非法：只允许小写字母、数字与下划线", n.Id)
	}
	if !semver.IsValid(n.Version) {
		return fmt.Errorf("[%s] version %q 不是合法 semver（应形如 v1.3.24）", n.Id, n.Version)
	}
	switch n.Kind {
	case KindNotice, KindAction, KindCheck:
	default:
		return fmt.Errorf("[%s] kind %q 非法", n.Id, n.Kind)
	}
	switch n.Level {
	case LevelHigh, LevelNormal, LevelLow:
	default:
		return fmt.Errorf("[%s] level %q 非法", n.Id, n.Level)
	}
	switch n.Apply.Type {
	case ApplyNone, ApplyNavigate:
		if n.Apply.Item != "" || n.Apply.Value != "" {
			return fmt.Errorf("[%s] apply.type=%s 不应带 item/value", n.Id, n.Apply.Type)
		}
	case ApplyConfigSet:
		if n.Apply.Item == "" || n.Apply.Value == "" {
			return fmt.Errorf("[%s] apply.type=config_set 必须同时给出 item 与 value", n.Id)
		}
	default:
		return fmt.Errorf("[%s] apply.type %q 非法", n.Id, n.Apply.Type)
	}
	if n.Apply.Type == ApplyNavigate && n.Page == "" {
		return fmt.Errorf("[%s] apply.type=navigate 必须给出 page", n.Id)
	}
	if n.Page != "" && !strings.HasPrefix(n.Page, "/") {
		return fmt.Errorf("[%s] page %q 必须是以 / 开头的站内相对路径", n.Id, n.Page)
	}
	if n.Doc != "" && !strings.HasPrefix(n.Doc, docPrefix) {
		return fmt.Errorf("[%s] doc %q 必须指向 %s", n.Id, n.Doc, docPrefix)
	}
	if err := validateText(n, "zh", n.ZH); err != nil {
		return err
	}
	return validateText(n, "en", n.EN)
}

// validateText 中英两套文案都必须齐全。
//
// kind=action 强制要求 effect_on / effect_off / revert 三项：
// "点了之后和不点有什么区别、后悔了怎么撤" 正是这个功能存在的理由，缺一项就不该发出去。
func validateText(n Note, lang string, t Text) error {
	if strings.TrimSpace(t.Title) == "" {
		return fmt.Errorf("[%s] %s.title 不能为空", n.Id, lang)
	}
	if strings.TrimSpace(t.Detail) == "" {
		return fmt.Errorf("[%s] %s.detail 不能为空", n.Id, lang)
	}
	if n.Kind != KindAction {
		return nil
	}
	if strings.TrimSpace(t.EffectOn) == "" {
		return fmt.Errorf("[%s] kind=action 时 %s.effect_on 必填（做了之后有什么变化）", n.Id, lang)
	}
	if strings.TrimSpace(t.EffectOff) == "" {
		return fmt.Errorf("[%s] kind=action 时 %s.effect_off 必填（不做会怎样，必须写代价）", n.Id, lang)
	}
	if strings.TrimSpace(t.Revert) == "" {
		return fmt.Errorf("[%s] kind=action 时 %s.revert 必填（怎么撤销）", n.Id, lang)
	}
	return nil
}

// DisplayVersion 把条目版本号归一化成给用户看的版本。
//
// 清单里的 version 必须填「首次包含该改动的构建号」，beta 阶段加的就填 beta 号
// （否则整个 beta 期都不会提示，见设计说明 §7）。但正式版用户在列表里看到
// v1.3.24-beta.15 会疑惑"我用的不是 beta 啊"，所以**存精确值、显示干净值**：
// 区间计算永远用原始值，只有展示这一层砍掉 -beta.x 后缀。
func DisplayVersion(v string) string {
	if !semver.IsValid(v) {
		return v
	}
	canonical := semver.Canonical(v)
	// Prerelease 返回带前导 '-' 的后缀（如 "-beta.15"），直接裁掉就是主版本号
	if pre := semver.Prerelease(canonical); pre != "" {
		return strings.TrimSuffix(canonical, pre)
	}
	return canonical
}

// RawVersionsFor 把用户在下拉里选的展示版本，还原成清单里所有对应的原始版本号。
//
// 列表按 version 列过滤，而库里存的是原始值（可能带 -beta.x），
// 前端传过来的是归一化后的值，两边对不上，必须在这里展开。
func RawVersionsFor(display string) []string {
	display = strings.TrimSpace(display)
	if display == "" {
		return nil
	}
	var out []string
	seen := make(map[string]bool)
	for _, n := range All() {
		if DisplayVersion(n.Version) != display || seen[n.Version] {
			continue
		}
		seen[n.Version] = true
		out = append(out, n.Version)
	}
	// 清单里找不到对应条目时，原样返回，让查询自然落空而不是退化成"不过滤"
	if len(out) == 0 {
		return []string{display}
	}
	return out
}

// Select 挑出本次启动应当生成的条目。
//
//	last 为空 + 全新安装      → 只取 fresh_install 条目（不倒历史，否则新用户一上来就被淹）
//	last 为空 + 存量库        → 只取"当前这一版"的条目（老用户首次升到带本功能的版本，起点未知）
//	last < current            → 取 (last, current] 区间内的非 fresh_install 条目
//	last >= current 或版本非法 → 不生成（降级路径只保留系统告警，见 service 层）
func Select(last, current string, freshInstall bool) []Note {
	return selectFrom(All(), last, current, freshInstall)
}

// selectFrom 是 Select 的纯函数内核，单测直接喂构造好的清单
func selectFrom(all []Note, last, current string, freshInstall bool) []Note {
	if !semver.IsValid(current) {
		return nil
	}
	out := make([]Note, 0, len(all))

	if strings.TrimSpace(last) == "" {
		for _, n := range all {
			if freshInstall {
				if n.FreshInstall {
					out = append(out, n)
				}
				continue
			}
			if !n.FreshInstall && semver.Compare(n.Version, current) == 0 {
				out = append(out, n)
			}
		}
		return out
	}

	if !semver.IsValid(last) || semver.Compare(last, current) >= 0 {
		return nil
	}
	for _, n := range all {
		if n.FreshInstall {
			continue
		}
		if semver.Compare(n.Version, last) > 0 && semver.Compare(n.Version, current) <= 0 {
			out = append(out, n)
		}
	}
	return out
}
