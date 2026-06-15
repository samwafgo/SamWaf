package wafai

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// goldenFile 由 SamWafAI 生成：uv run samwafai gen-golden --out wafai/testdata/feature_golden.json
type goldenFile struct {
	FeatureVersion string   `json:"feature_version"`
	FeatureNames   []string `json:"feature_names"`
	Cases          []struct {
		Method    string    `json:"method"`
		Path      string    `json:"path"`
		Query     string    `json:"query"`
		Body      string    `json:"body"`
		UserAgent string    `json:"user_agent"`
		Features  []float64 `json:"features"`
	} `json:"cases"`
}

// TestFeatureParity 校验 Go 特征提取与 Python（golden 文件）逐项一致。
// 这是 AI 检测正确性的基石：特征不对齐 -> 模型打分错乱。
func TestFeatureParity(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "feature_golden.json"))
	if err != nil {
		t.Fatalf("读取 golden 文件失败（请先运行 uv run samwafai gen-golden）: %v", err)
	}
	var g goldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("解析 golden 文件失败: %v", err)
	}

	if g.FeatureVersion != FeatureVersion {
		t.Fatalf("特征版本不一致: golden=%s go=%s", g.FeatureVersion, FeatureVersion)
	}
	if len(g.FeatureNames) != FeatureCount {
		t.Fatalf("特征维度不一致: golden=%d go=%d", len(g.FeatureNames), FeatureCount)
	}
	goNames := FeatureNames()
	for i, name := range g.FeatureNames {
		if goNames[i] != name {
			t.Fatalf("特征名[%d]不一致: golden=%s go=%s", i, name, goNames[i])
		}
	}

	const eps = 1e-9
	for ci, c := range g.Cases {
		got := ExtractFeatures(c.Method, c.Path, c.Query, c.Body, c.UserAgent)
		if len(got) != len(c.Features) {
			t.Fatalf("case[%d] 维度不一致: got=%d want=%d", ci, len(got), len(c.Features))
		}
		for fi := range got {
			if math.Abs(got[fi]-c.Features[fi]) > eps {
				t.Errorf("case[%d] 特征[%d:%s] 不一致: go=%.12f py=%.12f (path=%q query=%q)",
					ci, fi, goNames[fi], got[fi], c.Features[fi], c.Path, c.Query)
			}
		}
	}
}

func TestPercentDecode(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"%2e%2e", ".."},
		{"a+b", "a b"},
		{"%zz", "%zz"},
		{"%2", "%2"},
	}
	for _, c := range cases {
		if got := string(percentDecodeOnce([]byte(c.in))); got != c.want {
			t.Errorf("percentDecodeOnce(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestIterDecodeLayers(t *testing.T) {
	dec, layers := iterDecode([]byte("%252e%252e"))
	if string(dec) != ".." || layers != 2 {
		t.Errorf("iterDecode 双层解码失败: got=%q layers=%d", string(dec), layers)
	}
}

func TestCategoryHint(t *testing.T) {
	cases := []struct {
		method, path, query, body, ua string
		want                          string
	}{
		{"GET", "/p", "id=1' or '1'='1 union select", "", "", "SQL注入"},
		{"GET", "/c", "q=<script>alert(1)</script>", "", "", "XSS"},
		{"GET", "/d", "file=../../../../etc/passwd", "", "", "目录穿越"},
		{"GET", "/x", "host=127.0.0.1;cat /etc/passwd", "", "", "命令执行"},
		{"GET", "/", "page=1&sort=asc", "", "Mozilla/5.0", "异常请求"},
	}
	for _, c := range cases {
		f := ExtractFeatures(c.method, c.path, c.query, c.body, c.ua)
		if got := CategoryHint(f); got != c.want {
			t.Errorf("CategoryHint(query=%q)=%q want %q", c.query, got, c.want)
		}
	}
}

func TestFNV1a(t *testing.T) {
	if fnv1a32([]byte("")) != 2166136261 {
		t.Error("fnv1a32 空串错误")
	}
	if fnv1a32([]byte("a")) != 0xE40C292C {
		t.Errorf("fnv1a32('a')=%#x", fnv1a32([]byte("a")))
	}
}
