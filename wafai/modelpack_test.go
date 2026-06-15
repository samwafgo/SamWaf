package wafai

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadAndScore 端到端：加载 SamWafAI 产出的 .swai 模型，对正常/攻击请求打分。
// 模型由合成数据训练（examples/gen_synthetic.py），攻击样本应显著高于正常样本。
func TestLoadAndScore(t *testing.T) {
	swaiPath := filepath.Join("testdata", "sample_model.swai")
	if _, err := os.Stat(swaiPath); err != nil {
		t.Skip("无 sample_model.swai，跳过（由 SamWafAI pipeline 生成）")
	}

	d := NewDetector()
	if d.IsLoaded() {
		t.Fatal("新建检测器不应已加载")
	}
	// 未加载时打分应失败安全
	if res := d.PredictRequest("GET", "/", "id=1", "", ""); res.Loaded {
		t.Fatal("未加载模型时 Loaded 应为 false")
	}

	manifest, err := d.LoadFromFile(swaiPath)
	if err != nil {
		t.Fatalf("加载模型失败: %v", err)
	}
	if manifest.FeatureVersion != FeatureVersion {
		t.Fatalf("特征版本不一致: %s", manifest.FeatureVersion)
	}
	if !d.IsLoaded() {
		t.Fatal("加载后 IsLoaded 应为 true")
	}

	normal := d.PredictRequest("GET", "/products", "page=1&sort=asc", "", "Mozilla/5.0")
	attack := d.PredictRequest("GET", "/index.php", "id=1' or '1'='1 union select null,null--", "", "sqlmap/1.5")
	if !normal.Loaded || !attack.Loaded {
		t.Fatal("加载后打分应成功")
	}
	t.Logf("normal score=%.4f attack score=%.4f block_thr=%.4f", normal.Score, attack.Score, manifest.BlockThreshold)
	if attack.Score <= normal.Score {
		t.Errorf("攻击样本分数(%.4f)应高于正常样本(%.4f)", attack.Score, normal.Score)
	}

	d.Unload()
	if d.IsLoaded() {
		t.Fatal("卸载后 IsLoaded 应为 false")
	}
}

func TestRejectBadFeatureVersion(t *testing.T) {
	// 篡改 manifest 的特征版本应被拒绝（构造最小 zip）
	bad := buildTestPackage(t, `{"swai_format_version":1,"feature_version":"v999","model_type":"gbdt","model_file":"model_lgbm.txt","model_sha256":""}`, "dummy")
	d := NewDetector()
	if _, err := d.LoadFromBytes(bad); err == nil {
		t.Fatal("特征版本不匹配应加载失败")
	}
}

func TestRejectPathTraversalEntry(t *testing.T) {
	bad := buildTestPackageNamed(t, manifestName, `{"swai_format_version":1,"feature_version":"v1"}`, "../evil.txt", "x")
	d := NewDetector()
	if _, err := d.LoadFromBytes(bad); err == nil {
		t.Fatal("含路径穿越条目应加载失败")
	}
}
