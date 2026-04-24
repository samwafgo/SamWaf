package wafowasp

import (
	"SamWaf/common/zlog"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/corazawaf/coraza/v3"
)

// OwaspManager 管理 Coraza WAF 实例的生命周期与热重载。
//
// 热路径通过 Current() 原子读取当前活跃实例，写路径（Reload）用互斥锁串行化。
// Reload 过程中旧实例依然可用，新实例构建成功后原子替换，失败时保留旧实例。
type OwaspManager struct {
	current   atomic.Pointer[WafOWASP] // 当前活跃实例
	dir       string                   // WAF 数据根目录（绝对路径，其下应有 data/owasp/）
	mu        sync.Mutex               // 保证 Reload 串行
	active    atomic.Bool              // 是否处于激活态
	overrides *OverrideStore           // overrides 层存储
}

// NewOwaspManager 构造管理器并立刻尝试构建一次 WAF 实例。
// 若 WAF 初始化失败（如数据文件尚未释放），不会 panic，返回空 manager，
// 后续可通过 Reload() 再次尝试。
func NewOwaspManager(currentDir string) *OwaspManager {
	m := &OwaspManager{dir: currentDir}
	m.active.Store(true)
	m.overrides = NewOverrideStore(m.OverridesDir(), m.samwafDir())
	// 首次启动：若 overrides 目录不存在，生成默认 tuning 与 registry
	if err := m.overrides.EnsureDirAndDefaults(); err != nil {
		zlog.Error("EnsureDirAndDefaults overrides failed", map[string]interface{}{"error": err.Error()})
	}
	if err := m.Reload(); err != nil {
		zlog.Error("OwaspManager initial Reload failed", map[string]interface{}{"error": err.Error()})
	}
	// 同步一次引擎模式：读磁盘上的 tuning（即便 Reload 失败也读一次默认值），
	// 热路径据此决定 DetectionOnly 下是否记 INFO 日志
	if t, err := m.overrides.GetTuning(); err == nil {
		SetEngineMode(t.RuleEngine)
	}
	return m
}

// Overrides 获取 overrides 存储。
func (m *OwaspManager) Overrides() *OverrideStore {
	return m.overrides
}

// ApplyBaseConfig 写入 Layer 2 基线配置（samwaf/samwaf_base.json + samwaf/00-samwaf-base.conf）并触发热重载。
func (m *OwaspManager) ApplyBaseConfig(cfg BaseConfig) error {
	if m.overrides == nil {
		return fmt.Errorf("override store not initialized")
	}
	if err := m.overrides.SetBaseConfig(cfg); err != nil {
		return err
	}
	return m.Reload()
}

// ApplyTuning 写入新 tuning 并触发 WAF 热重载。失败时保留旧实例。
func (m *OwaspManager) ApplyTuning(t TuningConfig) error {
	if m.overrides == nil {
		return fmt.Errorf("override store not initialized")
	}
	if err := m.overrides.SetTuning(t); err != nil {
		return err
	}
	if err := m.Reload(); err != nil {
		return err
	}
	// 同步引擎模式，供热路径判定"DetectionOnly 本该拦截"时记 INFO 日志
	SetEngineMode(t.RuleEngine)
	return nil
}

// DisableRuleAndReload 禁用某规则并热重载。
func (m *OwaspManager) DisableRuleAndReload(id int, sourceFile string) error {
	if m.overrides == nil {
		return fmt.Errorf("override store not initialized")
	}
	if err := m.overrides.DisableRule(id, sourceFile); err != nil {
		return err
	}
	return m.Reload()
}

// EnableRuleAndReload 启用被禁用的规则并热重载。
func (m *OwaspManager) EnableRuleAndReload(id int) error {
	if m.overrides == nil {
		return fmt.Errorf("override store not initialized")
	}
	if err := m.overrides.EnableRule(id); err != nil {
		return err
	}
	return m.Reload()
}

// OverrideRuleAndReload 改写规则并热重载。
func (m *OwaspManager) OverrideRuleAndReload(id int, sourceFile, originalHash, content string) error {
	if m.overrides == nil {
		return fmt.Errorf("override store not initialized")
	}
	if err := m.overrides.OverrideRule(id, sourceFile, originalHash, content); err != nil {
		return err
	}
	return m.Reload()
}

// ResetRuleAndReload 还原规则并热重载。
func (m *OwaspManager) ResetRuleAndReload(id int) error {
	if m.overrides == nil {
		return fmt.Errorf("override store not initialized")
	}
	if err := m.overrides.ResetRule(id); err != nil {
		return err
	}
	return m.Reload()
}

// SetActive 设置全局激活状态。关闭后请求路径直接短路返回。
func (m *OwaspManager) SetActive(active bool) {
	m.active.Store(active)
	if w := m.current.Load(); w != nil {
		w.IsActive = active
	}
}

// IsActive 返回当前激活状态。
func (m *OwaspManager) IsActive() bool {
	return m.active.Load()
}

// Current 获取当前活跃实例（热路径，无锁）。可能为 nil（首次初始化失败时）。
func (m *OwaspManager) Current() *WafOWASP {
	return m.current.Load()
}

// Dir 返回 SamWaf 当前工作目录。
func (m *OwaspManager) Dir() string {
	return m.dir
}

// OwaspRoot 返回 data/owasp 根目录。
func (m *OwaspManager) OwaspRoot() string {
	return filepath.Join(m.dir, "data", "owasp")
}

// OverridesDir 返回 overrides/ 目录（Layer 3 用户自定义层）。
func (m *OwaspManager) OverridesDir() string {
	return filepath.Join(m.OwaspRoot(), "overrides")
}

// samwafDir 返回 samwaf/ 根目录（Layer 2 SamWaf 官方层）。
func (m *OwaspManager) samwafDir() string {
	return filepath.Join(m.OwaspRoot(), "samwaf")
}

// samwafHooksDir 返回 samwaf 钩子子目录（before 或 after）的路径。
// 仅在目录存在时才有效；不存在时调用方跳过即可，不视为错误。
func (m *OwaspManager) samwafHooksDir(sub string) string {
	return filepath.Join(m.samwafDir(), sub)
}

// loadDirConfs 将指定目录下所有 .conf 文件（按字典序）依次追加到 cfg。
// 目录不存在或为空时静默跳过。
func loadDirConfs(cfg coraza.WAFConfig, dir string) coraza.WAFConfig {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return cfg // 目录不存在，静默跳过
	}
	var confs []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".conf" {
			confs = append(confs, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(confs)
	for _, p := range confs {
		cfg = cfg.WithDirectivesFromFile(p)
	}
	return cfg
}

// Reload 重建 Coraza WAF 实例并原子替换。
//
// 完整加载顺序（优先级从低到高，后加载者覆盖同名变量）：
//
//  Layer 2 前置（SamWaf 官方，全部先于 Layer 3 加载）：
//  1. data/owasp/coraza.conf
//  2. data/owasp/coreruleset/crs-setup.conf
//  3. data/owasp/samwaf/before/*.conf        ← 全部 SamWaf 变量（字母序，00-samwaf-base.conf 先于 01-samwaf-init-vars.conf）
//     含：00-samwaf-base.conf（数值变量 paranoia/threshold，990001-990009）
//         01-samwaf-init-vars.conf（字符串变量 allowed_methods 等，991001-991099）
//
//  Layer 3 前置（用户设置，最后加载 → 优先级最高）：
//  4. data/owasp/overrides/05-user-vars.conf ← 用户所有覆盖（950001+ / 990100+）
//
//  ↑ 步骤 3-4 必须在 CRS rules 之前：CRS rule 901160 只在变量未设置时才写默认值。
//  ↑ Layer 3（步骤 4）加载最晚 → 同名变量用户值胜出，正确覆盖 Layer 2。
//
//  Layer 1（CRS 规则集）：
//  5. data/owasp/coreruleset/rules/*.conf
//
//  Layer 2 后置（SamWaf 官方补充，CRS 执行后）：
//  6. data/owasp/samwaf/after/*.conf         ← 补充检测（991100-991199）
//
//  Layer 3 后置（用户禁用 / 改写，须在 CRS 之后）：
//  7. data/owasp/overrides/10-disabled-rules.conf
//  8. data/owasp/overrides/20-custom-rules.conf
//
// 构建失败时旧实例保留，返回错误由调用方决定如何处理。
func (m *OwaspManager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	root := m.OwaspRoot()

	corazaConf := filepath.Join(root, "coraza.conf")
	if _, err := os.Stat(corazaConf); err != nil {
		return fmt.Errorf("coraza.conf not found at %s: %w", corazaConf, err)
	}

	cfg := coraza.NewWAFConfig().WithDirectivesFromFile(corazaConf)

	setupConf := filepath.Join(root, "coreruleset", "crs-setup.conf")
	if _, err := os.Stat(setupConf); err == nil {
		cfg = cfg.WithDirectivesFromFile(setupConf)
	} else {
		zlog.Error("crs-setup.conf missing, skipping", map[string]interface{}{"path": setupConf, "err": err.Error()})
	}

	// 步骤 3：Layer 2 before — samwaf/before/*.conf（按字母序，00-samwaf-base.conf 先于 01-samwaf-init-vars.conf）
	// 包含数值变量（paranoia/threshold）和字符串/列表变量（allowed_methods 等）。
	cfg = loadDirConfs(cfg, m.samwafHooksDir("before"))

	// 步骤 4：Layer 3 — overrides/05-user-vars.conf（用户覆盖层，最后加载 → 同名变量用户值胜出）
	// 覆盖 Layer 2 before 中的数值变量和字符串变量。
	tuningConf := filepath.Join(m.OverridesDir(), OverrideTuningFile)
	if _, err := os.Stat(tuningConf); err == nil {
		cfg = cfg.WithDirectivesFromFile(tuningConf)
	}

	// 步骤 5：Layer 1 — CRS 官方规则集（此时所有 tx.* 变量均已就绪）
	rulesGlob := filepath.Join(root, "coreruleset", "rules", "*.conf")
	cfg = cfg.WithDirectivesFromFile(rulesGlob)

	// 步骤 6：Layer 2 后置钩子（samwaf/after/*.conf，ID 991100-991199）—— CRS 规则执行后
	// 用途：补充检测规则、基于评分的自定义动作等。
	cfg = loadDirConfs(cfg, m.samwafHooksDir("after"))

	// 步骤 7-8：Layer 3 后置文件（用户禁用 / 改写规则，须在 CRS 规则之后才能 RemoveById）
	// 跳过已在步骤 4 提前加载的 pre-rules 文件。
	preRules := map[string]bool{
		OverrideTuningFile: true,
	}
	if overrides, err := listOverrideConfs(m.OverridesDir()); err == nil && len(overrides) > 0 {
		for _, p := range overrides {
			if preRules[filepath.Base(p)] {
				continue
			}
			cfg = cfg.WithDirectivesFromFile(p)
		}
	}

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return fmt.Errorf("failed to build coraza WAF: %w", err)
	}

	newInst := &WafOWASP{
		IsActive: m.active.Load(),
		WAF:      waf,
		logger:   &CustomLogger{},
	}
	old := m.current.Swap(newInst)
	if old != nil {
		// Coraza v3 没有显式 Close 方法；实例会被 GC 回收
		_ = old
	}
	zlog.Info("OwaspManager", "Coraza WAF reloaded successfully")
	return nil
}

// listOverrideConfs 列出 overrides 目录下所有 .conf，按字典序返回。
// 目录不存在或无文件时返回 nil 错误，空切片。
func listOverrideConfs(dir string) ([]string, error) {
	if dir == "" {
		return nil, errors.New("empty overrides dir")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) != ".conf" {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out, nil
}
