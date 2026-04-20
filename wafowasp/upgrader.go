package wafowasp

import (
	"SamWaf/common/zlog"
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// UpgradeConfig 升级所需的外部配置（通过 ConfigureUpgrader 由上层注入，避免 wafowasp → global 循环依赖）。
type UpgradeConfig struct {
	UpdateVersionURL string // 升级源根 URL，例如 http://update.samwaf.com/update/
	// NotifyFunc 当升级流程产生结果时被回调，可用于推送 WS 消息。success=false 表示失败。
	NotifyFunc func(success bool, msg string)
}

var upgradeCfg atomic.Pointer[UpgradeConfig]

// ConfigureUpgrader 注入升级所需上下文。main 启动阶段调用一次即可。
func ConfigureUpgrader(c UpgradeConfig) {
	cp := c
	upgradeCfg.Store(&cp)
}

func currentUpgradeCfg() UpgradeConfig {
	if c := upgradeCfg.Load(); c != nil {
		return *c
	}
	return UpgradeConfig{}
}

// UpgradeInfo 远端最新规则包的元数据。
type UpgradeInfo struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	URL            string `json:"url"`
	SHA256         string `json:"sha256"`
	Changelog      string `json:"changelog"`
	NeedUpdate     bool   `json:"need_update"`
	LastCheckAt    string `json:"last_check_at"`
}

// remoteManifest 从远端下载的 latest.json 反序列化结构。
type remoteManifest struct {
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Changelog string `json:"changelog"`
}

// upgrading 并发保护：一次只允许一个升级流程。
var upgrading atomic.Bool

// httpTimeout 下载 zip 的总超时（zip 可能较大，给 2 分钟）。
const httpTimeout = 2 * time.Minute

// CheckUpgrade 查询远端 latest.json 并返回对比结果。
//
// 升级源约定：{GUPDATE_VERSION_URL}owasp-ruleset/latest.json
// 响应：{"version": "1.0.20260401", "url": "...zip", "sha256": "...", "changelog": "..."}
func CheckUpgrade(m *OwaspManager) (*UpgradeInfo, error) {
	cur := ReadLocalVersion(m.OwaspRoot())
	info := &UpgradeInfo{
		CurrentVersion: cur,
		LastCheckAt:    time.Now().Format(time.RFC3339),
	}
	cfg := currentUpgradeCfg()
	if cfg.UpdateVersionURL == "" {
		return info, fmt.Errorf("未配置升级源 GUPDATE_VERSION_URL")
	}
	manifestURL := strings.TrimRight(cfg.UpdateVersionURL, "/") + "/owasp-ruleset/latest.json"
	manifest, err := fetchManifest(manifestURL)
	if err != nil {
		return info, err
	}
	info.LatestVersion = manifest.Version
	info.URL = manifest.URL
	info.SHA256 = manifest.SHA256
	info.Changelog = manifest.Changelog
	info.NeedUpdate = manifest.Version != "" && manifest.Version != cur
	return info, nil
}

// ApplyUpgrade 实施升级。流程：
//  1. CheckUpgrade 拿 manifest
//  2. 下载 zip，sha256 校验
//  3. 解压到 tmp/owasp-<ver>/
//  4. 备份当前 coreruleset → coreruleset.bak
//  5. 替换 coreruleset（保留 overrides）
//  6. 将 registry 里标记为 modified 的 ID 从新的 coreruleset 中移除（合并策略 "by_rule_id"）
//  7. 更新 version 文件
//  8. m.Reload()
//  9. 失败时恢复备份
func ApplyUpgrade(m *OwaspManager) error {
	if !upgrading.CompareAndSwap(false, true) {
		return fmt.Errorf("正在升级中，请稍后")
	}
	defer upgrading.Store(false)

	if currentUpgradeCfg().UpdateVersionURL == "" {
		return fmt.Errorf("未配置升级源 GUPDATE_VERSION_URL")
	}

	owaspRoot := m.OwaspRoot()

	info, err := CheckUpgrade(m)
	if err != nil {
		return err
	}
	if !info.NeedUpdate {
		return fmt.Errorf("当前已是最新版本: %s", info.CurrentVersion)
	}
	if info.URL == "" {
		return fmt.Errorf("远端未提供 URL")
	}

	// 下载 zip 到 tmp
	tmpDir := filepath.Join(owaspRoot, "tmp")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("mkdir tmp: %w", err)
	}
	zipPath := filepath.Join(tmpDir, fmt.Sprintf("owasp-%s.zip", info.LatestVersion))
	if err := downloadFile(info.URL, zipPath); err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	defer os.Remove(zipPath)

	if info.SHA256 != "" {
		actual, err := fileSHA256(zipPath)
		if err != nil {
			return fmt.Errorf("sha256 失败: %w", err)
		}
		if !strings.EqualFold(actual, info.SHA256) {
			return fmt.Errorf("sha256 校验不通过，预期 %s, 实际 %s", info.SHA256, actual)
		}
	}

	// 解压
	extractDir := filepath.Join(tmpDir, fmt.Sprintf("owasp-%s", info.LatestVersion))
	_ = os.RemoveAll(extractDir)
	if err := unzip(zipPath, extractDir); err != nil {
		return fmt.Errorf("解压失败: %w", err)
	}
	defer os.RemoveAll(extractDir)

	// 合并：从新 coreruleset 中剔除用户 modified 的规则块（保留用户版本）
	reg, _ := m.Overrides().LoadRegistry()
	modifiedIDs := collectModifiedIDs(reg)
	if len(modifiedIDs) > 0 {
		if err := stripRulesInDir(extractDir, modifiedIDs); err != nil {
			return fmt.Errorf("合并用户改动失败: %w", err)
		}
	}

	// 备份 + 替换 coreruleset
	coreDir := filepath.Join(owaspRoot, "coreruleset")
	backupDir := filepath.Join(owaspRoot, "coreruleset.bak")
	_ = os.RemoveAll(backupDir)
	if _, err := os.Stat(coreDir); err == nil {
		if err := os.Rename(coreDir, backupDir); err != nil {
			return fmt.Errorf("备份 coreruleset 失败: %w", err)
		}
	}

	// 解压目录下可能是 coreruleset/ 直接结构，也可能是 <name>/coreruleset/；
	// 这里尝试自动识别。
	srcCore, err := resolveCorerulesetInExtract(extractDir)
	if err != nil {
		// 回滚
		if _, statErr := os.Stat(backupDir); statErr == nil {
			_ = os.Rename(backupDir, coreDir)
		}
		return fmt.Errorf("定位 coreruleset 目录失败: %w", err)
	}
	if err := os.Rename(srcCore, coreDir); err != nil {
		// 回滚
		if _, statErr := os.Stat(backupDir); statErr == nil {
			_ = os.Rename(backupDir, coreDir)
		}
		return fmt.Errorf("应用新 coreruleset 失败: %w", err)
	}

	// 写 version 文件
	if err := os.WriteFile(filepath.Join(owaspRoot, "version"), []byte(info.LatestVersion), 0644); err != nil {
		zlog.Error("写入 version 文件失败", map[string]interface{}{"err": err.Error()})
	}

	// 刷新规则解析缓存，触发热重载
	InvalidateRuleCache()
	if err := m.Reload(); err != nil {
		// reload 失败时尝试回滚到备份
		_ = os.RemoveAll(coreDir)
		if _, statErr := os.Stat(backupDir); statErr == nil {
			_ = os.Rename(backupDir, coreDir)
		}
		InvalidateRuleCache()
		_ = m.Reload()
		return fmt.Errorf("升级后 Reload 失败，已回滚: %w", err)
	}

	_ = os.RemoveAll(backupDir)
	return nil
}

// NotifyUpgradeResult 将升级结果通过注入的 NotifyFunc 推送（WS / 消息队列等）。
// 如果上层未调用 ConfigureUpgrader 注入 NotifyFunc，则仅记录日志。
func NotifyUpgradeResult(success bool, msg string) {
	cfg := currentUpgradeCfg()
	if cfg.NotifyFunc != nil {
		cfg.NotifyFunc(success, msg)
	} else {
		zlog.Info("OWASP 升级结果", map[string]interface{}{"success": success, "msg": msg})
	}
}

// ReadLocalVersion 读取 data/owasp/version；缺失返回 "unknown"。
func ReadLocalVersion(owaspRoot string) string {
	data, err := os.ReadFile(filepath.Join(owaspRoot, "version"))
	if err != nil {
		return "unknown"
	}
	v := strings.TrimSpace(string(data))
	if v == "" {
		return "unknown"
	}
	return v
}

// ---- 辅助 ----

var fetchClient = &http.Client{Timeout: httpTimeout}
var fetchOnce sync.Once

func fetchManifest(url string) (*remoteManifest, error) {
	fetchOnce.Do(func() {})
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := fetchClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest HTTP %d", resp.StatusCode)
	}
	var m remoteManifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

func downloadFile(url, dst string) error {
	resp, err := fetchClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// unzip 解压 zip 到 dst 目录。安全检查：拒绝 zip slip。
func unzip(src, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	cleanDst, _ := filepath.Abs(dst)
	for _, f := range r.File {
		target := filepath.Join(dst, f.Name)
		absTarget, _ := filepath.Abs(target)
		if !strings.HasPrefix(absTarget, cleanDst) {
			return fmt.Errorf("zip slip detected: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, f.Mode()); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			rc.Close()
			out.Close()
			return err
		}
		rc.Close()
		out.Close()
	}
	return nil
}

func resolveCorerulesetInExtract(dir string) (string, error) {
	// 优先检查 dir/coreruleset/
	if st, err := os.Stat(filepath.Join(dir, "coreruleset")); err == nil && st.IsDir() {
		return filepath.Join(dir, "coreruleset"), nil
	}
	// 否则看是否 zip 顶层就是 rules/ + crs-setup.conf
	if st, err := os.Stat(filepath.Join(dir, "rules")); err == nil && st.IsDir() {
		return dir, nil
	}
	// 再向下一层找第一个包含 rules/ 的目录
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cand := filepath.Join(dir, e.Name())
		if st, err := os.Stat(filepath.Join(cand, "rules")); err == nil && st.IsDir() {
			return cand, nil
		}
		if st, err := os.Stat(filepath.Join(cand, "coreruleset")); err == nil && st.IsDir() {
			return filepath.Join(cand, "coreruleset"), nil
		}
	}
	return "", fmt.Errorf("zip 内找不到 coreruleset 或 rules 目录")
}

func collectModifiedIDs(reg *OverrideRegistry) map[int]struct{} {
	out := map[int]struct{}{}
	if reg == nil {
		return out
	}
	for k, v := range reg.Rules {
		if v.Action != OverrideModified {
			continue
		}
		id := 0
		for _, ch := range k {
			if ch < '0' || ch > '9' {
				id = 0
				break
			}
			id = id*10 + int(ch-'0')
		}
		if id > 0 {
			out[id] = struct{}{}
		}
	}
	return out
}

// stripRulesInDir 遍历 dir 下所有 .conf，将文件中指定 ID 的 SecRule/SecAction 块删除。
// 用于升级时在新官方规则包中移除用户已改写的规则 ID，避免加载两份引起冲突。
func stripRulesInDir(dir string, ids map[int]struct{}) error {
	if len(ids) == 0 {
		return nil
	}
	return filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(info.Name()) != ".conf" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		newData, changed := removeRulesByID(string(data), ids)
		if !changed {
			return nil
		}
		return os.WriteFile(p, []byte(newData), info.Mode())
	})
}

// removeRulesByID 删除内容中命中 ID 的 SecRule/SecAction 块。
// 简单实现：按行走一遍，发现 SecRule/SecAction 起始且 ID 命中则跳过整块（直到第一个不以 \ 结尾的行）。
func removeRulesByID(content string, ids map[int]struct{}) (string, bool) {
	lines := strings.Split(content, "\n")
	var out []string
	changed := false

	i := 0
	for i < len(lines) {
		line := lines[i]
		trimmed := strings.TrimLeft(line, " \t")
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "secrule") || strings.HasPrefix(lower, "secaction") {
			// 收集整个块
			start := i
			block := []string{line}
			for endsWithBackslash(line) && i+1 < len(lines) {
				i++
				line = lines[i]
				block = append(block, line)
			}
			// 检查块内是否包含目标 ID
			blockText := strings.Join(block, "\n")
			hit := false
			if m := reID.FindStringSubmatch(blockText); len(m) == 2 {
				id := 0
				for _, ch := range m[1] {
					id = id*10 + int(ch-'0')
				}
				if _, ok := ids[id]; ok {
					hit = true
				}
			}
			if hit {
				changed = true
				i++
				_ = start
				continue
			}
			out = append(out, block...)
			i++
			continue
		}
		out = append(out, line)
		i++
	}
	if !changed {
		return content, false
	}
	return strings.Join(out, "\n"), true
}
