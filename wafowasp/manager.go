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
	m.overrides = NewOverrideStore(m.OverridesDir())
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

// OverridesDir 返回 overrides/ 目录（用户改动层）。
func (m *OwaspManager) OverridesDir() string {
	return filepath.Join(m.OwaspRoot(), "overrides")
}

// Reload 重建 Coraza WAF 实例并原子替换。
//
// 加载顺序（顺序决定 Phase 1 规则链的执行先后）：
//  1. data/owasp/coraza.conf                （基础配置）
//  2. data/owasp/coreruleset/crs-setup.conf （CRS 配置，定义变量注释占位）
//  3. data/owasp/overrides/00-tuning.conf   （SamWaf 参数调优，含 tx.* 变量初始化）
//     ↑ 必须在 CRS rules 之前：CRS REQUEST-901-INITIALIZATION.conf 的 rule 901160 会检查
//     "&TX:allowed_methods @eq 0"，只有变量 未设置 时才写默认值；我们在此提前设置，
//     901160 就会跳过默认值，我们的值才能生效。
//  4. data/owasp/coreruleset/rules/*.conf   （官方规则集，包括 901160 初始化和 911100 检查）
//  5. data/owasp/overrides/10-*.conf 等     （SecRuleRemoveById 和用户自定义规则，须在规则之后）
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

	// 步骤 3：提前加载 00-tuning.conf（变量初始化）
	// 必须在 rules/*.conf 之前，否则 tx.* 变量会被 CRS 默认初始化规则覆盖
	tuningConf := filepath.Join(m.OverridesDir(), OverrideTuningFile)
	if _, err := os.Stat(tuningConf); err == nil {
		cfg = cfg.WithDirectivesFromFile(tuningConf)
	}

	// 步骤 4：加载 CRS 官方规则集
	rulesGlob := filepath.Join(root, "coreruleset", "rules", "*.conf")
	cfg = cfg.WithDirectivesFromFile(rulesGlob)

	// 步骤 5：加载其余 overrides（禁用/改写规则，须在 CRS 规则之后才能 RemoveById）
	// 跳过已在步骤 3 提前加载的 00-tuning.conf
	if overrides, err := listOverrideConfs(m.OverridesDir()); err == nil && len(overrides) > 0 {
		for _, p := range overrides {
			if filepath.Base(p) == OverrideTuningFile {
				continue // 已在 CRS rules 之前加载，跳过
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
