package wafowasp

import (
	"archive/zip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"SamWaf/common/zlog"
)

func TestMain(m *testing.M) {
	zlog.InitZLog(false, "console")
	os.Exit(m.Run())
}

// ---- 辅助 ----

// buildZip 在 dst 路径创建一个 ZIP，entries 是 zip内路径→文件内容的映射。
// 以 "/" 结尾的 key 视为目录条目。
func buildZip(t *testing.T, dst string, entries map[string]string) {
	t.Helper()
	f, err := os.Create(dst)
	if err != nil {
		t.Fatalf("buildZip create: %v", err)
	}
	w := zip.NewWriter(f)
	for name, content := range entries {
		if strings.HasSuffix(name, "/") {
			_, _ = w.Create(name)
			continue
		}
		fw, err := w.Create(name)
		if err != nil {
			t.Fatalf("buildZip entry %s: %v", name, err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatalf("buildZip write %s: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("buildZip close: %v", err)
	}
	_ = f.Close()
}

// minimalOwaspRoot 初始化一个能让 Reload() 成功的最小 owaspRoot 目录。
// 返回 owaspRoot 路径。
func minimalOwaspRoot(t *testing.T, baseDir string) string {
	t.Helper()
	owaspRoot := filepath.Join(baseDir, "data", "owasp")
	rulesDir := filepath.Join(owaspRoot, "coreruleset", "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	// coraza.conf 最小有效内容
	must(t, os.WriteFile(filepath.Join(owaspRoot, "coraza.conf"),
		[]byte("SecRuleEngine On\n"), 0644))
	// crs-setup.conf 空文件即可
	must(t, os.WriteFile(filepath.Join(owaspRoot, "coreruleset", "crs-setup.conf"),
		[]byte(""), 0644))
	// 一条最简单的规则
	must(t, os.WriteFile(filepath.Join(rulesDir, "old-rule.conf"),
		[]byte("SecAction \"id:900001,phase:1,pass,nolog\"\n"), 0644))
	// 初始版本
	must(t, os.WriteFile(filepath.Join(owaspRoot, "version"),
		[]byte("1.0.20260101"), 0644))
	return owaspRoot
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ---- resolveCorerulesetInExtract ----

func TestResolveCorerulesetInExtract_Flat(t *testing.T) {
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "coreruleset", "rules"), 0755))

	got, err := resolveCorerulesetInExtract(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != filepath.Join(dir, "coreruleset") {
		t.Errorf("got %s, want %s", got, filepath.Join(dir, "coreruleset"))
	}
}

func TestResolveCorerulesetInExtract_Nested(t *testing.T) {
	// ZIP 含顶层包装目录（如 owasp-1.0.20260422/coreruleset/）
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "owasp-1.0.20260422", "coreruleset", "rules"), 0755))

	got, err := resolveCorerulesetInExtract(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(dir, "owasp-1.0.20260422", "coreruleset")
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestResolveCorerulesetInExtract_RulesAtRoot(t *testing.T) {
	// ZIP 顶层就是 rules/ + crs-setup.conf（coreruleset 自身作为顶层）
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "rules"), 0755))
	must(t, os.WriteFile(filepath.Join(dir, "crs-setup.conf"), []byte(""), 0644))

	got, err := resolveCorerulesetInExtract(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != dir {
		t.Errorf("got %s, want %s (dir itself)", got, dir)
	}
}

func TestResolveCorerulesetInExtract_NotFound(t *testing.T) {
	dir := t.TempDir()
	// 空目录，找不到 coreruleset

	_, err := resolveCorerulesetInExtract(dir)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

// ---- removeRulesByID ----

func TestRemoveRulesByID_RemovesMatchedBlock(t *testing.T) {
	content := "SecRule ARGS \"@contains foo\" \\\n    \"id:941100,phase:2,deny\"\nSecRule ARGS \"@contains bar\" \\\n    \"id:941200,phase:2,deny\"\n"
	ids := map[int]struct{}{941100: {}}

	got, changed := removeRulesByID(content, ids)
	if !changed {
		t.Error("changed should be true")
	}
	if strings.Contains(got, "941100") {
		t.Error("id 941100 should have been stripped")
	}
	if !strings.Contains(got, "941200") {
		t.Error("id 941200 should remain")
	}
}

func TestRemoveRulesByID_NoMatchLeaveContentUnchanged(t *testing.T) {
	content := "SecRule ARGS \"@contains foo\" \\\n    \"id:941100,phase:2,deny\"\n"
	ids := map[int]struct{}{999999: {}}

	_, changed := removeRulesByID(content, ids)
	if changed {
		t.Error("changed should be false when no ID matches")
	}
}

func TestRemoveRulesByID_EmptyIDs(t *testing.T) {
	content := "SecRule ARGS \"@contains foo\" \\\n    \"id:941100,phase:2,deny\"\n"

	_, changed := removeRulesByID(content, map[int]struct{}{})
	if changed {
		t.Error("changed should be false for empty id set")
	}
}

// ---- lock.txt 检测 ----

func TestApplyUpgrade_LockFileBlocks(t *testing.T) {
	baseDir := t.TempDir()
	m := &OwaspManager{dir: baseDir}
	owaspRoot := m.OwaspRoot()
	must(t, os.MkdirAll(owaspRoot, 0755))
	must(t, os.WriteFile(filepath.Join(owaspRoot, "lock.txt"), []byte("locked"), 0644))

	ConfigureUpgrader(UpgradeConfig{UpdateVersionURL: "http://127.0.0.1:19999/"})
	err := ApplyUpgrade(m)
	if err == nil {
		t.Fatal("expected error due to lock.txt, got nil")
	}
	if !strings.Contains(err.Error(), "lock.txt") {
		t.Errorf("error should mention lock.txt, got: %v", err)
	}
}

// ---- 端到端升级（平铺 ZIP 结构）----

func TestApplyUpgrade_EndToEnd_FlatZip(t *testing.T) {
	baseDir := t.TempDir()
	owaspRoot := minimalOwaspRoot(t, baseDir)

	// 构建升级 ZIP（平铺，无包装目录）
	zipPath := filepath.Join(t.TempDir(), "owasp-1.0.20260422.zip")
	buildZip(t, zipPath, map[string]string{
		"coreruleset/crs-setup.conf":      "",
		"coreruleset/rules/new-rule.conf": "SecAction \"id:900002,phase:1,pass,nolog\"\n",
		"samwaf/before/01-init.conf":      "# before hook\n",
		"samwaf/after/99-custom.conf":     "# after hook\n",
	})
	zipBytes, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owasp-ruleset/latest.json":
			fmt.Fprintf(w, `{"version":"1.0.20260422","url":"http://%s/owasp-ruleset/owasp-1.0.20260422.zip","sha256":"","changelog":"test"}`, r.Host)
		case "/owasp-ruleset/owasp-1.0.20260422.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	m := &OwaspManager{dir: baseDir}
	m.active.Store(true)
	m.overrides = NewOverrideStore(m.OverridesDir(), filepath.Join(m.OwaspRoot(), "samwaf"))

	ConfigureUpgrader(UpgradeConfig{UpdateVersionURL: srv.URL + "/"})
	err = ApplyUpgrade(m)

	// Reload 可能因为简化规则失败，但文件操作应已完成（失败则回滚）
	if err != nil && !strings.Contains(err.Error(), "Reload") {
		t.Fatalf("ApplyUpgrade returned unexpected error: %v", err)
	}

	if err == nil {
		// 升级成功：校验文件已到位
		assertFileExists(t, owaspRoot, "coreruleset/rules/new-rule.conf")
		assertFileNotExists(t, owaspRoot, "coreruleset/rules/old-rule.conf")
		assertVersion(t, owaspRoot, "1.0.20260422")
		assertFileExists(t, owaspRoot, "samwaf/before/01-init.conf")
		assertFileExists(t, owaspRoot, "samwaf/after/99-custom.conf")
	} else {
		// Reload 失败回滚：旧 coreruleset 应恢复
		assertFileExists(t, owaspRoot, "coreruleset/rules/old-rule.conf")
	}
}

// TestApplyUpgrade_EndToEnd_NestedZip 验证 ZIP 含顶层包装目录时
// samwaf 路径能被正确识别（即本次 bug 修复的覆盖场景）。
func TestApplyUpgrade_EndToEnd_NestedZip(t *testing.T) {
	baseDir := t.TempDir()
	owaspRoot := minimalOwaspRoot(t, baseDir)

	// 构建升级 ZIP（含包装目录 owasp-1.0.20260422/）
	zipPath := filepath.Join(t.TempDir(), "owasp-1.0.20260422.zip")
	buildZip(t, zipPath, map[string]string{
		"owasp-1.0.20260422/coreruleset/crs-setup.conf":      "",
		"owasp-1.0.20260422/coreruleset/rules/new-rule.conf": "SecAction \"id:900002,phase:1,pass,nolog\"\n",
		"owasp-1.0.20260422/samwaf/before/01-init.conf":      "# before hook\n",
		"owasp-1.0.20260422/samwaf/after/99-custom.conf":     "# after hook\n",
	})
	zipBytes, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owasp-ruleset/latest.json":
			fmt.Fprintf(w, `{"version":"1.0.20260422","url":"http://%s/owasp-ruleset/owasp-1.0.20260422.zip","sha256":"","changelog":"test"}`, r.Host)
		case "/owasp-ruleset/owasp-1.0.20260422.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	m := &OwaspManager{dir: baseDir}
	m.active.Store(true)
	m.overrides = NewOverrideStore(m.OverridesDir(), filepath.Join(m.OwaspRoot(), "samwaf"))

	ConfigureUpgrader(UpgradeConfig{UpdateVersionURL: srv.URL + "/"})
	err = ApplyUpgrade(m)

	if err != nil && !strings.Contains(err.Error(), "Reload") {
		t.Fatalf("ApplyUpgrade returned unexpected error: %v", err)
	}

	if err == nil {
		// coreruleset 和 samwaf 都应该从包装目录内正确提取
		assertFileExists(t, owaspRoot, "coreruleset/rules/new-rule.conf")
		assertFileExists(t, owaspRoot, "samwaf/before/01-init.conf")
		assertFileExists(t, owaspRoot, "samwaf/after/99-custom.conf")
		assertVersion(t, owaspRoot, "1.0.20260422")
	} else {
		// 回滚：旧 coreruleset 应恢复
		assertFileExists(t, owaspRoot, "coreruleset/rules/old-rule.conf")
	}
}

// TestApplyUpgrade_RulesNotEmptyAfterUpgrade 专门验证升级后 rules/ 目录不为空。
func TestApplyUpgrade_RulesNotEmptyAfterUpgrade(t *testing.T) {
	baseDir := t.TempDir()
	minimalOwaspRoot(t, baseDir)

	// ZIP 包含多条规则文件
	zipPath := filepath.Join(t.TempDir(), "owasp-1.0.20260422.zip")
	buildZip(t, zipPath, map[string]string{
		"coreruleset/crs-setup.conf":             "",
		"coreruleset/rules/REQUEST-901.conf":     "SecAction \"id:900001,phase:1,pass,nolog\"\n",
		"coreruleset/rules/REQUEST-941-XSS.conf": "SecAction \"id:900002,phase:2,pass,nolog\"\n",
		"coreruleset/rules/RESPONSE-950.conf":    "SecAction \"id:900003,phase:4,pass,nolog\"\n",
	})
	zipBytes, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owasp-ruleset/latest.json":
			fmt.Fprintf(w, `{"version":"1.0.20260422","url":"http://%s/owasp-ruleset/owasp-1.0.20260422.zip","sha256":"","changelog":""}`, r.Host)
		case "/owasp-ruleset/owasp-1.0.20260422.zip":
			_, _ = w.Write(zipBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	m := &OwaspManager{dir: baseDir}
	m.active.Store(true)
	m.overrides = NewOverrideStore(m.OverridesDir(), filepath.Join(m.OwaspRoot(), "samwaf"))

	ConfigureUpgrader(UpgradeConfig{UpdateVersionURL: srv.URL + "/"})
	err = ApplyUpgrade(m)

	owaspRoot := m.OwaspRoot()
	if err == nil {
		// 升级成功：rules/ 必须有文件
		entries, readErr := os.ReadDir(filepath.Join(owaspRoot, "coreruleset", "rules"))
		if readErr != nil {
			t.Fatalf("coreruleset/rules not accessible: %v", readErr)
		}
		if len(entries) == 0 {
			t.Error("coreruleset/rules is empty after upgrade — this is the reported bug")
		}
		for _, e := range entries {
			info, _ := e.Info()
			if info.Size() == 0 {
				t.Errorf("rules/%s is a zero-byte file after upgrade", e.Name())
			}
		}
	} else if !strings.Contains(err.Error(), "Reload") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestApplyUpgrade_RollbackOnReloadFailure 验证 Reload 失败时备份被恢复。
func TestApplyUpgrade_RollbackOnReloadFailure(t *testing.T) {
	baseDir := t.TempDir()
	owaspRoot := minimalOwaspRoot(t, baseDir)

	// ZIP 里放一条会让 Coraza 解析失败的无效指令
	zipPath := filepath.Join(t.TempDir(), "owasp-1.0.20260422.zip")
	buildZip(t, zipPath, map[string]string{
		"coreruleset/crs-setup.conf": "",
		"coreruleset/rules/bad.conf": "THIS IS NOT VALID CORAZA SYNTAX !!!\n",
	})
	zipBytes, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owasp-ruleset/latest.json":
			fmt.Fprintf(w, `{"version":"1.0.20260422","url":"http://%s/owasp-ruleset/owasp-1.0.20260422.zip","sha256":"","changelog":""}`, r.Host)
		case "/owasp-ruleset/owasp-1.0.20260422.zip":
			_, _ = w.Write(zipBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	m := &OwaspManager{dir: baseDir}
	m.active.Store(true)
	m.overrides = NewOverrideStore(m.OverridesDir(), filepath.Join(m.OwaspRoot(), "samwaf"))

	ConfigureUpgrader(UpgradeConfig{UpdateVersionURL: srv.URL + "/"})
	err = ApplyUpgrade(m)

	if err == nil {
		t.Skip("Coraza accepted invalid rule; rollback test not applicable")
		return
	}
	if !strings.Contains(err.Error(), "Reload") {
		t.Fatalf("expected Reload error, got: %v", err)
	}

	// 回滚：旧 coreruleset 应恢复，rules/ 有旧文件
	assertFileExists(t, owaspRoot, "coreruleset/rules/old-rule.conf")
	// 版本文件应已写入（在 Reload 之前写），但回滚不管 version；此处仅验证文件系统
}

// ---- assert helpers ----

func assertFileExists(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if _, err := os.Stat(p); err != nil {
		t.Errorf("expected file %s to exist: %v", rel, err)
	}
}

func assertFileNotExists(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if _, err := os.Stat(p); err == nil {
		t.Errorf("expected file %s to be absent, but it exists", rel)
	}
}

func assertVersion(t *testing.T, owaspRoot, want string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(owaspRoot, "version"))
	if err != nil {
		t.Errorf("version file not readable: %v", err)
		return
	}
	if got := strings.TrimSpace(string(data)); got != want {
		t.Errorf("version = %q, want %q", got, want)
	}
}
