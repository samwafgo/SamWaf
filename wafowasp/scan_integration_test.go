package wafowasp

import (
	"path/filepath"
	"runtime"
	"testing"
)

// 集成测试：扫描仓库内真实的 CRS 规则目录，打印每个文件的规则数，用来检查解析是否漏规则。
// 需要 cmd/samwaf/exedata/owasp 已释放。CI 上若不存在会跳过。
func TestScanRealCRS(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Dir(filepath.Dir(thisFile)) // .../SamWaf
	owaspRoot := filepath.Join(repoRoot, "cmd", "samwaf", "exedata", "owasp")

	files, err := ScanAllRules(owaspRoot)
	if err != nil {
		t.Skipf("skip: scan owasp: %v", err)
	}
	if len(files) == 0 {
		t.Skip("skip: no .conf under cmd/samwaf/exedata/owasp")
	}

	total := 0
	for _, f := range files {
		t.Logf("%-80s rules=%d", f.File, len(f.Rules))
		total += len(f.Rules)
	}
	t.Logf("TOTAL conf files=%d rules=%d", len(files), total)
}
