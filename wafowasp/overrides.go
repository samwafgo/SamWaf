package wafowasp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OverrideAuditLogFile 变更日志文件名。
const OverrideAuditLogFile = "audit_log.json"

// maxAuditEntries 审计日志最大保留条数，超出时裁剪最旧的。
const maxAuditEntries = 1000

// AuditAction 审计动作类型。
type AuditAction string

const (
	AuditDisabled AuditAction = "disabled" // 禁用规则
	AuditEnabled  AuditAction = "enabled"  // 启用规则
	AuditModified AuditAction = "modified" // 改写规则
	AuditReset    AuditAction = "reset"    // 还原规则
	AuditTuning   AuditAction = "tuning"   // 调整全局参数
)

// AuditLogEntry 单条变更记录。
type AuditLogEntry struct {
	Time       string      `json:"time"`              // RFC3339
	RuleID     int         `json:"rule_id,omitempty"` // 0 表示非规则级操作（如 tuning）
	Action     AuditAction `json:"action"`
	SourceFile string      `json:"source_file,omitempty"` // 规则来源文件（仅规则操作）
	Note       string      `json:"note,omitempty"`        // 附加说明
}

// auditLogFile 内存中的日志文件结构（序列化用）。
type auditLogFile struct {
	Version int             `json:"version"`
	Entries []AuditLogEntry `json:"entries"`
}

// AppendAuditLog 追加一条变更记录到 audit_log.json（持有锁调用，线程安全）。
func (s *OverrideStore) AppendAuditLog(entry AuditLogEntry) {
	// 不阻塞调用方；写失败仅打印，不影响规则操作
	if entry.Time == "" {
		entry.Time = time.Now().Format(time.RFC3339)
	}
	path := filepath.Join(s.dir, OverrideAuditLogFile)

	var af auditLogFile
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &af)
	}
	if af.Entries == nil {
		af.Entries = []AuditLogEntry{}
	}
	af.Version = 1
	af.Entries = append(af.Entries, entry)
	// 裁剪超出上限的旧记录
	if len(af.Entries) > maxAuditEntries {
		af.Entries = af.Entries[len(af.Entries)-maxAuditEntries:]
	}
	if data, err := json.MarshalIndent(af, "", "  "); err == nil {
		_ = atomicWriteFile(path, data)
	}
}

// LoadAuditLog 读取变更日志（倒序返回，最新在前）。
func (s *OverrideStore) LoadAuditLog() ([]AuditLogEntry, error) {
	path := filepath.Join(s.dir, OverrideAuditLogFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditLogEntry{}, nil
		}
		return nil, err
	}
	var af auditLogFile
	if err := json.Unmarshal(data, &af); err != nil {
		return nil, err
	}
	// 倒序
	entries := af.Entries
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries, nil
}

// Override 相关的文件名，集中在此以便升级器、API 层复用。
//
// 三层策略叠加（加载顺序）：
//
//	Layer 1 (基线):        coreruleset/rules/*.conf      ← CRS 上游，在线升级时整体替换
//	Layer 2 (SamWaf 官方): samwaf/00-samwaf-base.conf   ← SamWaf 数值变量，由 samwaf_base.json 驱动
//	                       samwaf/before/*.conf          ← SamWaf 字符串/列表变量
//	                       samwaf/after/*.conf           ← SamWaf 补充检测规则
//	Layer 3 (用户):        overrides/05-user-vars.conf  ← 用户 tx.* 变量，优先于 Layer 2（永不被升级覆盖）
//	                       overrides/10-disabled-rules.conf
//	                       overrides/20-custom-rules.conf
//
// 重要：Layer 2 和 Layer 3 均须在 rules/*.conf 之前加载，原因：
// CRS REQUEST-901-INITIALIZATION.conf 的 rule 901160 检查"变量未设置时才写默认值"，
// 必须在它之前 setvar，否则 tx.allowed_methods 等设置永远无效。
const (
	// Layer 2 — SamWaf 官方层（文件在 samwaf/ 下，随 SamWaf 版本更新）
	SamWafBaseConfFile = "00-samwaf-base.conf" // 由 samwaf_base.json 生成的数值变量 conf
	SamWafBaseJSONFile = "samwaf_base.json"    // Layer 2 配置持久化源（paranoia/threshold 等）

	// Layer 3 — 用户自定义层（文件在 overrides/ 下，永不被升级覆盖）
	OverrideTuningFile   = "05-user-vars.conf"      // 用户 tx.* 变量覆盖层
	OverrideDisabledFile = "10-disabled-rules.conf" // 用户按 ID 禁用的规则
	OverrideCustomFile   = "20-custom-rules.conf"   // 用户覆盖/自定义的规则
	OverrideRegistryFile = "override_registry.json" // 元数据：所有用户改动的单一事实来源

	OverrideRegistryShema = 1
)

// OverrideAction 用户对某条规则的动作。
type OverrideAction string

const (
	OverrideDisabled OverrideAction = "disabled" // 通过 SecRuleRemoveById 关闭
	OverrideModified OverrideAction = "modified" // 用户改写过内容
)

// RuleOverrideEntry registry.json 中单条规则记录。
type RuleOverrideEntry struct {
	Action       OverrideAction `json:"action"`
	SourceFile   string         `json:"source_file"`             // 规则原本所在文件（rules/REQUEST-942-*.conf）
	OriginalHash string         `json:"original_hash,omitempty"` // 修改类操作记录原内容 sha256，用于后续升级时比对
	Content      string         `json:"content,omitempty"`       // modified 时保存用户编辑后内容（单条完整 SecRule 块）
	UpdatedAt    string         `json:"updated_at"`
}

// TuningConfig 全局调优参数。
type TuningConfig struct {
	BlockingParanoia     int    `json:"blocking_paranoia_level"`  // 1..4
	DetectionParanoia    int    `json:"detection_paranoia_level"` // >= blocking
	InboundThreshold     int    `json:"inbound_anomaly_score_threshold"`
	OutboundThreshold    int    `json:"outbound_anomaly_score_threshold"`
	RuleEngine           string `json:"rule_engine"`                 // On / DetectionOnly / Off
	EarlyBlocking        int    `json:"early_blocking"`              // 0/1
	EnforceBodyProcessor int    `json:"enforce_bodyproc_urlencoded"` // 0/1
	// CustomVars 用户自定义 CRS 事务变量（如 tx.allowed_methods）。
	// key 不含 tx. 前缀（如 "allowed_methods"），value 为字符串值。
	// 写入 00-tuning.conf 时以 SecAction setvar:'tx.KEY=VALUE' 形式追加。
	CustomVars map[string]string `json:"custom_vars,omitempty"`
}

// DefaultTuning 首次运行时写入的宽松默认值，较官方默认更容忍误报。
// 引擎模式默认为 DetectionOnly（观察模式），避免新部署时误伤正常流量。
// 用户确认规则无误报后，可在后台手动切换到 On（拦截模式）。
func DefaultTuning() TuningConfig {
	return TuningConfig{
		BlockingParanoia:  1,
		DetectionParanoia: 2,
		InboundThreshold:  7, // 官方默认 5，我们放宽到 7，降低单条 critical 直接 block 的概率
		OutboundThreshold: 4,
		RuleEngine:        "DetectionOnly",
		EarlyBlocking:     0,
	}
}

// BaseConfig Layer 1 的持久化参数。仅包含 CRS tx.* 数值变量，
// 不含 SecRuleEngine（属于用户运营决策）和 CustomVars（属于 Layer 2）。
type BaseConfig struct {
	BlockingParanoia     int `json:"blocking_paranoia_level"`
	DetectionParanoia    int `json:"detection_paranoia_level"`
	InboundThreshold     int `json:"inbound_anomaly_score_threshold"`
	OutboundThreshold    int `json:"outbound_anomaly_score_threshold"`
	EarlyBlocking        int `json:"early_blocking"`
	EnforceBodyProcessor int `json:"enforce_bodyproc_urlencoded"`
}

// DefaultBaseConfig Layer 1 出厂默认值（与 DefaultTuning 数值部分保持一致）。
func DefaultBaseConfig() BaseConfig {
	d := DefaultTuning()
	return BaseConfig{
		BlockingParanoia:  d.BlockingParanoia,
		DetectionParanoia: d.DetectionParanoia,
		InboundThreshold:  d.InboundThreshold,
		OutboundThreshold: d.OutboundThreshold,
		EarlyBlocking:     d.EarlyBlocking,
	}
}

// toTuningConfig 将 BaseConfig 转为 TuningConfig 以便复用 writeSamWafBaseConfFile。
func (b BaseConfig) toTuningConfig() TuningConfig {
	return TuningConfig{
		BlockingParanoia:     b.BlockingParanoia,
		DetectionParanoia:    b.DetectionParanoia,
		InboundThreshold:     b.InboundThreshold,
		OutboundThreshold:    b.OutboundThreshold,
		EarlyBlocking:        b.EarlyBlocking,
		EnforceBodyProcessor: b.EnforceBodyProcessor,
	}
}

// GetBaseConfig 读取 Layer 2 基线配置（来自 samwaf/samwaf_base.json）。
// 文件不存在时返回 DefaultBaseConfig()（不视为错误）。
func (s *OverrideStore) GetBaseConfig() (BaseConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return loadBaseConfigLocked(filepath.Join(s.samwafDir, SamWafBaseJSONFile))
}

func loadBaseConfigLocked(path string) (BaseConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultBaseConfig(), nil
		}
		return BaseConfig{}, err
	}
	var cfg BaseConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return BaseConfig{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// SetBaseConfig 持久化 Layer 2 配置并重新生成 samwaf/before/00-samwaf-base.conf。
// 调用方（ApplyBaseConfig）负责触发 Reload()。
func (s *OverrideStore) SetBaseConfig(cfg BaseConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(filepath.Join(s.samwafDir, SamWafBaseJSONFile), data); err != nil {
		return fmt.Errorf("write %s: %w", SamWafBaseJSONFile, err)
	}
	if err := writeSamWafBaseConfFile(filepath.Join(s.samwafDir, "before", SamWafBaseConfFile), cfg.toTuningConfig()); err != nil {
		return fmt.Errorf("write %s: %w", SamWafBaseConfFile, err)
	}
	s.AppendAuditLog(AuditLogEntry{
		Action: AuditTuning,
		Note: fmt.Sprintf("base_config: blocking_pl=%d detection_pl=%d inbound=%d outbound=%d",
			cfg.BlockingParanoia, cfg.DetectionParanoia, cfg.InboundThreshold, cfg.OutboundThreshold),
	})
	return nil
}

// OverrideRegistry overrides 层的元数据。
type OverrideRegistry struct {
	Version int                          `json:"version"`
	Rules   map[string]RuleOverrideEntry `json:"rules"`
	Global  TuningConfig                 `json:"global"`

	// 记录升级时应保留的已删除文件，升级逻辑据此跳过新写。
	DeletedFiles []string `json:"deleted_files,omitempty"`
}

// OverrideStore 封装 Layer 2（samwaf/）和 Layer 3（overrides/）的读写，内部持锁串行以避免并发写坏文件。
type OverrideStore struct {
	dir       string     // overrides/ 目录绝对路径（Layer 3 用户层）
	samwafDir string     // samwaf/ 目录绝对路径（Layer 2 SamWaf 官方层）
	mu        sync.Mutex // 写锁
}

// NewOverrideStore 创建一个 OverrideStore，不会立即触达磁盘。
// overridesDir 是 Layer 3 用户层目录（overrides/），samwafDir 是 Layer 2 SamWaf 官方层目录（samwaf/）。
func NewOverrideStore(overridesDir, samwafDir string) *OverrideStore {
	return &OverrideStore{dir: overridesDir, samwafDir: samwafDir}
}

// Dir 返回 overrides 目录路径。
func (s *OverrideStore) Dir() string {
	return s.dir
}

// EnsureDirAndDefaults 确保各层目录存在并写入各层默认文件。
//
// 行为：
//   - samwaf/before/00-samwaf-base.conf（Layer 2）：每次调用均重写，确保 SamWaf 产品默认值随二进制更新。
//   - overrides/05-user-vars.conf（Layer 3）：仅首次（registry 缺失时）写入；后续由用户操作写入。
//   - 兼容迁移：若发现旧版 overrides/samwaf_base.json，自动移到 samwaf/samwaf_base.json。
//   - 兼容迁移：若发现旧版 samwaf/00-samwaf-base.conf，删除（会在 samwaf/before/ 重新生成）。
//   - 兼容迁移：若发现旧版 overrides/00-tuning.conf，自动重命名为 overrides/05-user-vars.conf。
func (s *OverrideStore) EnsureDirAndDefaults() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return fmt.Errorf("mkdir overrides: %w", err)
	}
	if err := os.MkdirAll(s.samwafDir, 0755); err != nil {
		return fmt.Errorf("mkdir samwaf: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(s.samwafDir, "before"), 0755); err != nil {
		return fmt.Errorf("mkdir samwaf/before: %w", err)
	}

	// 兼容迁移：旧版将 samwaf_base.json 放在 overrides/，新版移到 samwaf/。
	oldBaseJSON := filepath.Join(s.dir, SamWafBaseJSONFile)
	newBaseJSON := filepath.Join(s.samwafDir, SamWafBaseJSONFile)
	if _, err := os.Stat(oldBaseJSON); err == nil {
		if _, err2 := os.Stat(newBaseJSON); os.IsNotExist(err2) {
			_ = os.Rename(oldBaseJSON, newBaseJSON)
		} else {
			_ = os.Remove(oldBaseJSON)
		}
	}
	// 旧版 overrides/00-samwaf-base.conf 不再在此目录生成，清理占位。
	oldOverridesConf := filepath.Join(s.dir, SamWafBaseConfFile)
	if _, err := os.Stat(oldOverridesConf); err == nil {
		_ = os.Remove(oldOverridesConf)
	}
	// 旧版 samwaf/00-samwaf-base.conf（中间迁移路径），现改为 samwaf/before/，删除旧文件。
	oldSamwafConf := filepath.Join(s.samwafDir, SamWafBaseConfFile)
	if _, err := os.Stat(oldSamwafConf); err == nil {
		_ = os.Remove(oldSamwafConf)
	}

	// Layer 2：从 samwaf/samwaf_base.json 读取配置（不存在时用出厂默认值），生成 samwaf/before/00-samwaf-base.conf。
	// samwaf_base.json 可由 API 修改，因此每次启动只重新生成 .conf 文件而不覆盖 .json。
	baseJSONPath := newBaseJSON
	baseCfg, _ := loadBaseConfigLocked(baseJSONPath)
	// 首次运行：写入出厂默认值到 samwaf/samwaf_base.json
	if _, err := os.Stat(baseJSONPath); os.IsNotExist(err) {
		if data, err2 := json.MarshalIndent(baseCfg, "", "  "); err2 == nil {
			_ = atomicWriteFile(baseJSONPath, data)
		}
	}
	basePath := filepath.Join(s.samwafDir, "before", SamWafBaseConfFile)
	if err := writeSamWafBaseConfFile(basePath, baseCfg.toTuningConfig()); err != nil {
		return fmt.Errorf("write %s: %w", SamWafBaseConfFile, err)
	}

	// 兼容迁移：旧版使用 00-tuning.conf，自动重命名为 05-user-vars.conf。
	oldTuning := filepath.Join(s.dir, "00-tuning.conf")
	newTuning := filepath.Join(s.dir, OverrideTuningFile)
	if _, err := os.Stat(oldTuning); err == nil {
		if _, err2 := os.Stat(newTuning); os.IsNotExist(err2) {
			_ = os.Rename(oldTuning, newTuning)
		} else {
			// 两者都存在（异常情况）：保留新文件，删除旧文件。
			_ = os.Remove(oldTuning)
		}
	}

	regPath := filepath.Join(s.dir, OverrideRegistryFile)
	_, statErr := os.Stat(regPath)
	regExists := statErr == nil

	if !regExists {
		reg := &OverrideRegistry{
			Version: OverrideRegistryShema,
			Rules:   map[string]RuleOverrideEntry{},
			Global:  DefaultTuning(),
		}
		if err := writeRegistryLocked(regPath, reg); err != nil {
			return err
		}
		// Layer 2：05-user-vars.conf 仅首次写入（后续由用户操作写入）。
		if _, err := os.Stat(newTuning); os.IsNotExist(err) {
			if err := writeTuningConfFile(newTuning, reg.Global); err != nil {
				return err
			}
		}
	}

	// 保证 10-disabled-rules.conf 占位文件存在（避免 coraza 加载空 glob 时报错）。
	disabledPath := filepath.Join(s.dir, OverrideDisabledFile)
	if _, err := os.Stat(disabledPath); os.IsNotExist(err) {
		if err := os.WriteFile(disabledPath, []byte(disabledHeader()), 0644); err != nil {
			return err
		}
	}

	return nil
}

// LoadRegistry 读取 registry.json。文件不存在时返回零值 registry（不视为错误）。
func (s *OverrideStore) LoadRegistry() (*OverrideRegistry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return loadRegistryLocked(filepath.Join(s.dir, OverrideRegistryFile))
}

func loadRegistryLocked(path string) (*OverrideRegistry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &OverrideRegistry{
				Version: OverrideRegistryShema,
				Rules:   map[string]RuleOverrideEntry{},
				Global:  DefaultTuning(),
			}, nil
		}
		return nil, err
	}
	reg := &OverrideRegistry{}
	if err := json.Unmarshal(data, reg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if reg.Rules == nil {
		reg.Rules = map[string]RuleOverrideEntry{}
	}
	return reg, nil
}

// SaveRegistry 原子写入 registry.json。
func (s *OverrideStore) SaveRegistry(reg *OverrideRegistry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeRegistryLocked(filepath.Join(s.dir, OverrideRegistryFile), reg)
}

func writeRegistryLocked(path string, reg *OverrideRegistry) error {
	if reg.Version == 0 {
		reg.Version = OverrideRegistryShema
	}
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data)
}

// SetTuning 更新 tuning 参数：刷新 registry.global 和 overrides/00-tuning.conf 两处。
func (s *OverrideStore) SetTuning(t TuningConfig) error {
	if err := s.setTuningNoLog(t); err != nil {
		return err
	}
	s.AppendAuditLog(AuditLogEntry{
		Action: AuditTuning,
		Note: fmt.Sprintf("blocking_pl=%d detection_pl=%d inbound_threshold=%d engine=%s",
			t.BlockingParanoia, t.DetectionParanoia, t.InboundThreshold, t.RuleEngine),
	})
	return nil
}

// setTuningNoLog 内部实现，无审计日志（供 SetCRSVar/DeleteCRSVar 调用，避免重复日志）。
func (s *OverrideStore) setTuningNoLog(t TuningConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	regPath := filepath.Join(s.dir, OverrideRegistryFile)
	reg, err := loadRegistryLocked(regPath)
	if err != nil {
		return err
	}
	reg.Global = t
	if err := writeRegistryLocked(regPath, reg); err != nil {
		return err
	}
	return writeTuningConfFile(filepath.Join(s.dir, OverrideTuningFile), t)
}

// GetTuning 读取当前 tuning（来自 registry）。
func (s *OverrideStore) GetTuning() (TuningConfig, error) {
	reg, err := s.LoadRegistry()
	if err != nil {
		return TuningConfig{}, err
	}
	return reg.Global, nil
}

// GetCRSVars 返回当前所有自定义 CRS 事务变量（key 不含 tx. 前缀）。
func (s *OverrideStore) GetCRSVars() (map[string]string, error) {
	t, err := s.GetTuning()
	if err != nil {
		return nil, err
	}
	if t.CustomVars == nil {
		return map[string]string{}, nil
	}
	return t.CustomVars, nil
}

// SetCRSVar 设置单个 CRS 事务变量并触发 tuning 重写。
// key 可以带或不带 tx. 前缀，内部统一存储为不带前缀的形式。
func (s *OverrideStore) SetCRSVar(key, value string) error {
	key = strings.TrimPrefix(key, "tx.")
	if key == "" {
		return fmt.Errorf("variable key must not be empty")
	}
	t, err := s.GetTuning()
	if err != nil {
		return err
	}
	if t.CustomVars == nil {
		t.CustomVars = map[string]string{}
	}
	oldVal := t.CustomVars[key]
	t.CustomVars[key] = value
	if err := s.setTuningNoLog(t); err != nil {
		return err
	}
	s.AppendAuditLog(AuditLogEntry{
		Action: AuditTuning,
		Note:   fmt.Sprintf("set crs_var tx.%s: %q → %q", key, oldVal, value),
	})
	return nil
}

// DeleteCRSVar 删除单个 CRS 事务变量并触发 tuning 重写。
func (s *OverrideStore) DeleteCRSVar(key string) error {
	key = strings.TrimPrefix(key, "tx.")
	if key == "" {
		return fmt.Errorf("variable key must not be empty")
	}
	t, err := s.GetTuning()
	if err != nil {
		return err
	}
	if _, ok := t.CustomVars[key]; !ok {
		return nil
	}
	oldVal := t.CustomVars[key]
	delete(t.CustomVars, key)
	if err := s.setTuningNoLog(t); err != nil {
		return err
	}
	s.AppendAuditLog(AuditLogEntry{
		Action: AuditTuning,
		Note:   fmt.Sprintf("delete crs_var tx.%s (was %q)", key, oldVal),
	})
	return nil
}

// DisableRule 禁用单条规则。实现方式：在 10-disabled-rules.conf 里追加 SecRuleRemoveById。
// 同一 ID 重复调用等价于幂等，不会重复追加。
func (s *OverrideStore) DisableRule(id int, sourceFile string) error {
	if id <= 0 {
		return fmt.Errorf("invalid rule id: %d", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	reg, err := loadRegistryLocked(filepath.Join(s.dir, OverrideRegistryFile))
	if err != nil {
		return err
	}
	reg.Rules[strconv.Itoa(id)] = RuleOverrideEntry{
		Action:     OverrideDisabled,
		SourceFile: sourceFile,
		UpdatedAt:  time.Now().Format(time.RFC3339),
	}
	if err := writeRegistryLocked(filepath.Join(s.dir, OverrideRegistryFile), reg); err != nil {
		return err
	}
	if err := rewriteDisabledConfLocked(s.dir, reg); err != nil {
		return err
	}
	s.AppendAuditLog(AuditLogEntry{
		RuleID:     id,
		Action:     AuditDisabled,
		SourceFile: sourceFile,
		Note:       "SecRuleRemoveById 写入 10-disabled-rules.conf",
	})
	return nil
}

// EnableRule 取消禁用（从 registry 移除 action=disabled 记录；modified 保留）。
func (s *OverrideStore) EnableRule(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	reg, err := loadRegistryLocked(filepath.Join(s.dir, OverrideRegistryFile))
	if err != nil {
		return err
	}
	key := strconv.Itoa(id)
	if entry, ok := reg.Rules[key]; ok && entry.Action == OverrideDisabled {
		srcFile := entry.SourceFile
		delete(reg.Rules, key)
		if err := writeRegistryLocked(filepath.Join(s.dir, OverrideRegistryFile), reg); err != nil {
			return err
		}
		if err := rewriteDisabledConfLocked(s.dir, reg); err != nil {
			return err
		}
		s.AppendAuditLog(AuditLogEntry{
			RuleID:     id,
			Action:     AuditEnabled,
			SourceFile: srcFile,
			Note:       "从 10-disabled-rules.conf 移除 SecRuleRemoveById",
		})
	}
	return nil
}

// OverrideRule 用户改写规则。content 应是完整的 SecRule/SecAction 块字符串。
// 内部策略：
//   - 注册为 modified，保存原内容 hash 和新内容
//   - 在 20-custom-rules.conf 中按 ID 聚合写入（重复 ID 覆盖）
//   - 额外在 10-disabled-rules.conf 里对该 ID 执行 SecRuleRemoveById（先删再加，避免 ID 冲突）
func (s *OverrideStore) OverrideRule(id int, sourceFile, originalHash, content string) error {
	if id <= 0 {
		return fmt.Errorf("invalid rule id: %d", id)
	}
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("content is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	reg, err := loadRegistryLocked(filepath.Join(s.dir, OverrideRegistryFile))
	if err != nil {
		return err
	}
	reg.Rules[strconv.Itoa(id)] = RuleOverrideEntry{
		Action:       OverrideModified,
		SourceFile:   sourceFile,
		OriginalHash: originalHash,
		Content:      content,
		UpdatedAt:    time.Now().Format(time.RFC3339),
	}
	if err := writeRegistryLocked(filepath.Join(s.dir, OverrideRegistryFile), reg); err != nil {
		return err
	}
	if err := rewriteDisabledConfLocked(s.dir, reg); err != nil {
		return err
	}
	if err := rewriteCustomConfLocked(s.dir, reg); err != nil {
		return err
	}
	s.AppendAuditLog(AuditLogEntry{
		RuleID:     id,
		Action:     AuditModified,
		SourceFile: sourceFile,
		Note:       "用户改写内容写入 20-custom-rules.conf",
	})
	return nil
}

// ResetRule 还原某条规则为上游版本（从 registry 和所有 overrides 文件中删除）。
func (s *OverrideStore) ResetRule(id int) error {
	if id <= 0 {
		return fmt.Errorf("invalid rule id: %d", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	reg, err := loadRegistryLocked(filepath.Join(s.dir, OverrideRegistryFile))
	if err != nil {
		return err
	}
	key := strconv.Itoa(id)
	oldEntry, existed := reg.Rules[key]
	if !existed {
		return nil
	}
	srcFile := oldEntry.SourceFile
	delete(reg.Rules, key)
	if err := writeRegistryLocked(filepath.Join(s.dir, OverrideRegistryFile), reg); err != nil {
		return err
	}
	if err := rewriteDisabledConfLocked(s.dir, reg); err != nil {
		return err
	}
	if err := rewriteCustomConfLocked(s.dir, reg); err != nil {
		return err
	}
	s.AppendAuditLog(AuditLogEntry{
		RuleID:     id,
		Action:     AuditReset,
		SourceFile: srcFile,
		Note:       "还原为上游版本，移除所有 override 记录",
	})
	return nil
}

// ApplyRegistryToFiles 基于当前 registry 重新生成所有 overrides 的 .conf 文件（用于手工修复 / 升级后同步）。
func (s *OverrideStore) ApplyRegistryToFiles() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	reg, err := loadRegistryLocked(filepath.Join(s.dir, OverrideRegistryFile))
	if err != nil {
		return err
	}
	if err := writeTuningConfFile(filepath.Join(s.dir, OverrideTuningFile), reg.Global); err != nil {
		return err
	}
	if err := rewriteDisabledConfLocked(s.dir, reg); err != nil {
		return err
	}
	return rewriteCustomConfLocked(s.dir, reg)
}

// rewriteDisabledConfLocked 从 registry 派生 10-disabled-rules.conf。
// 同时禁用 action=disabled 和 action=modified 的 ID（modified 需要先 RemoveById 才能用 custom 文件里的新版本替代）。
func rewriteDisabledConfLocked(dir string, reg *OverrideRegistry) error {
	var sb strings.Builder
	sb.WriteString(disabledHeader())

	// 收集需要 remove 的 ID
	ids := make([]int, 0, len(reg.Rules))
	for k := range reg.Rules {
		id, err := strconv.Atoi(k)
		if err != nil || id <= 0 {
			continue
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		entry := reg.Rules[strconv.Itoa(id)]
		switch entry.Action {
		case OverrideDisabled:
			sb.WriteString(fmt.Sprintf("# disabled by user (source: %s) at %s\n", entry.SourceFile, entry.UpdatedAt))
			sb.WriteString(fmt.Sprintf("SecRuleRemoveById %d\n\n", id))
		case OverrideModified:
			sb.WriteString(fmt.Sprintf("# replaced by user (source: %s) at %s; see %s\n", entry.SourceFile, entry.UpdatedAt, OverrideCustomFile))
			sb.WriteString(fmt.Sprintf("SecRuleRemoveById %d\n\n", id))
		}
	}
	return atomicWriteFile(filepath.Join(dir, OverrideDisabledFile), []byte(sb.String()))
}

// rewriteCustomConfLocked 重写 20-custom-rules.conf，收录所有 modified 条目的用户版本。
func rewriteCustomConfLocked(dir string, reg *OverrideRegistry) error {
	var sb strings.Builder
	sb.WriteString(customHeader())

	ids := make([]int, 0, len(reg.Rules))
	for k := range reg.Rules {
		id, err := strconv.Atoi(k)
		if err != nil || id <= 0 {
			continue
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		entry := reg.Rules[strconv.Itoa(id)]
		if entry.Action != OverrideModified {
			continue
		}
		sb.WriteString(fmt.Sprintf("# --- user override for rule id=%d (source: %s) updated_at=%s ---\n", id, entry.SourceFile, entry.UpdatedAt))
		sb.WriteString(strings.TrimRight(entry.Content, "\n"))
		sb.WriteString("\n\n")
	}
	return atomicWriteFile(filepath.Join(dir, OverrideCustomFile), []byte(sb.String()))
}

// =============================================================================
// SamWaf SecAction/SecRule ID 分配表（全局，禁止跨层冲突）
//
//	ID 范围           层               文件
//	900000–989999    CRS (Layer 1)    coreruleset/rules/*.conf  （禁止使用）
//	990001–990009    Layer 2          samwaf/00-samwaf-base.conf（paranoia/threshold）
//	990100–990999    Layer 3          overrides/05-user-vars.conf（用户自定义 CRS 变量）
//	991001–991099    Layer 2          samwaf/before/*.conf（CRS 变量初始化，如 allowed_methods）
//	991100–991199    Layer 2          samwaf/after/*.conf（补充检测规则）
//	950001–950006    Layer 3          overrides/05-user-vars.conf（调参：paranoia/threshold 覆盖）
//	                                  注：CRS 从 950010 开始，950001-950006 实测无冲突
//
// 验证结论（2026-04-21）：
//   CRS 4.x 实际 rule ID 范围 901001~980170，没有落在 990xxx / 991xxx / 950001-950006 段。
// =============================================================================

// writeSamWafBaseConfFile 生成 Layer 2 文件 samwaf/before/00-samwaf-base.conf：SamWaf 基线 tx.* 数值变量。
//
// 仅设置 paranoia level / anomaly threshold 等数值参数；
// 不包含 SecRuleEngine（用户运营决策）和字符串/列表型变量（由 samwaf/before/01-samwaf-init-vars.conf 负责）。
// 使用 ID 段 990001–990009（CRS 安全区）。
func writeSamWafBaseConfFile(path string, t TuningConfig) error {
	var sb strings.Builder
	sb.WriteString("# Layer 2: SamWaf product defaults (numeric). Managed by SamWaf, updated with SamWaf releases.\n")
	sb.WriteString("# DO NOT EDIT MANUALLY. To override, use 后台 → OWASP 规则管理 → 全局调参。\n")
	sb.WriteString("# User settings in overrides/05-user-vars.conf take precedence (loaded after this file).\n")
	sb.WriteString("# ID range: 990001-990009 (SamWaf Layer 2 base, safe above CRS max 980170)\n\n")

	writeSetvar := func(id int, desc, name string, value int) {
		if value <= 0 {
			return
		}
		sb.WriteString(fmt.Sprintf("# %s\n", desc))
		sb.WriteString(fmt.Sprintf("SecAction \\\n    \"id:%d,\\\n    phase:1,\\\n    pass,\\\n    nolog,\\\n    t:none,\\\n    tag:'SamWaf_base',\\\n    setvar:'tx.%s=%d'\"\n\n", id, name, value))
	}

	writeSetvar(990001, "Blocking Paranoia Level", "blocking_paranoia_level", t.BlockingParanoia)
	if t.DetectionParanoia >= t.BlockingParanoia {
		writeSetvar(990002, "Detection Paranoia Level", "detection_paranoia_level", t.DetectionParanoia)
	}
	writeSetvar(990003, "Inbound Anomaly Score Threshold", "inbound_anomaly_score_threshold", t.InboundThreshold)
	writeSetvar(990004, "Outbound Anomaly Score Threshold", "outbound_anomaly_score_threshold", t.OutboundThreshold)
	if t.EarlyBlocking == 1 {
		writeSetvar(990005, "Early Blocking", "early_blocking", 1)
	}
	if t.EnforceBodyProcessor == 1 {
		writeSetvar(990006, "Enforce Body Processor URLENCODED", "enforce_bodyproc_urlencoded", 1)
	}

	return atomicWriteFile(path, []byte(sb.String()))
}

// writeTuningConfFile 根据 TuningConfig 生成 Layer 3 文件（overrides/05-user-vars.conf）。
//
// 包含用户设置的全部内容：SecRuleEngine、tx.* 数值调参变量、用户自定义字符串变量。
// 加载顺序在 samwaf/00-samwaf-base.conf 和 samwaf/before/*.conf 之后，同名变量以本文件为准。
// ID 段：调参变量 950001-950006；用户自定义 CRS 变量 990100-990999（上限约 900 条）。
// 注：CRS 实际从 950010 开始，950001-950006 无冲突（已验证）。
func writeTuningConfFile(path string, t TuningConfig) error {
	var sb strings.Builder
	sb.WriteString("# Layer 3: User variable overrides. Managed by SamWaf via API. NEVER overwritten by any upgrade.\n")
	sb.WriteString("# Use 后台 → OWASP 规则管理 → 全局调参 来修改这里的内容。\n")
	sb.WriteString("# Values here take precedence over samwaf/00-samwaf-base.conf (SamWaf defaults).\n\n")

	// RuleEngine: DetectionOnly/On/Off 通过 SecRuleEngine 指令直接设定
	engine := strings.TrimSpace(t.RuleEngine)
	if engine == "" {
		engine = "On"
	}
	sb.WriteString(fmt.Sprintf("SecRuleEngine %s\n\n", engine))

	writeSetvar := func(id int, desc, name string, value int) {
		if value <= 0 {
			return
		}
		sb.WriteString(fmt.Sprintf("# %s\n", desc))
		sb.WriteString(fmt.Sprintf("SecAction \\\n    \"id:%d,\\\n    phase:1,\\\n    pass,\\\n    nolog,\\\n    t:none,\\\n    tag:'SamWaf_tuning',\\\n    setvar:'tx.%s=%d'\"\n\n", id, name, value))
	}

	writeSetvar(950001, "Blocking Paranoia Level", "blocking_paranoia_level", t.BlockingParanoia)
	if t.DetectionParanoia >= t.BlockingParanoia {
		writeSetvar(950002, "Detection Paranoia Level", "detection_paranoia_level", t.DetectionParanoia)
	}
	writeSetvar(950003, "Inbound Anomaly Score Threshold", "inbound_anomaly_score_threshold", t.InboundThreshold)
	writeSetvar(950004, "Outbound Anomaly Score Threshold", "outbound_anomaly_score_threshold", t.OutboundThreshold)
	if t.EarlyBlocking == 1 {
		writeSetvar(950005, "Early Blocking", "early_blocking", 1)
	}
	if t.EnforceBodyProcessor == 1 {
		writeSetvar(950006, "Enforce Body Processor URLENCODED", "enforce_bodyproc_urlencoded", 1)
	}

	// 用户自定义 CRS 事务变量（tx.allowed_methods 等）
	// 按 key 排序保证文件内容稳定，从 ID 950100 起步
	if len(t.CustomVars) > 0 {
		keys := make([]string, 0, len(t.CustomVars))
		for k := range t.CustomVars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteString("# --- User-defined CRS transaction variables ---\n")
		for i, k := range keys {
			v := t.CustomVars[k]
			varName := k
			if !strings.HasPrefix(varName, "tx.") {
				varName = "tx." + k
			}
			// 使用 990100+ 段：CRS 最高占用到 980xxx，990xxx 段不会与任何 CRS 规则 ID 冲突
			id := 990100 + i
			sb.WriteString(fmt.Sprintf("# CRS variable: %s\n", varName))
			sb.WriteString(fmt.Sprintf("SecAction \\\n    \"id:%d,\\\n    phase:1,\\\n    pass,\\\n    nolog,\\\n    t:none,\\\n    tag:'SamWaf_crsvar',\\\n    setvar:'%s=%s'\"\n\n", id, varName, v))
		}
	}

	return atomicWriteFile(path, []byte(sb.String()))
}

func disabledHeader() string {
	return "# Auto-generated by SamWaf. Contains SecRuleRemoveById for user-disabled rules.\n# DO NOT EDIT MANUALLY; use 后台 → OWASP 规则管理 界面操作。\n\n"
}

func customHeader() string {
	return "# Auto-generated by SamWaf. Contains user-overridden / custom SecRule blocks.\n# DO NOT EDIT MANUALLY; use 后台 → OWASP 规则管理 界面操作。\n\n"
}

// atomicWriteFile 通过 tmp + rename 的方式原子写文件。
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".override-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
