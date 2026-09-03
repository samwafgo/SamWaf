package wafenginecore

import (
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"strings"
	"testing"
)

// 回归：平均速率模式下，冷启动(LoadHost)与热更新(ApplyAntiCCConfig)曾各写一遍构造逻辑，
// 其中一处把 AntiCC.Rate（语义是「时间窗口秒数」）当成了每秒速率。
// 表现为：界面上点一次保存，实际阈值就变；重启之后又变回去，用户无从自查。
// 现在两条路径都走 BuildIPRateLimiter，这里把「速率必须是 Limit/Rate」钉死。

func newAntiCC(mode string, window, limit int) model.AntiCC {
	return model.AntiCC{
		BaseOrm:   baseorm.BaseOrm{Id: "test-anticc-id"},
		Rate:      window,
		Limit:     limit,
		LimitMode: mode,
	}
}

func TestBuildIPRateLimiter_RateModeUsesLimitPerWindow(t *testing.T) {
	cases := []struct {
		window, limit int
		wantRate      float64
	}{
		{60, 100, 100.0 / 60.0}, // 曾经的错误实现会得到 60
		{10, 250, 25},
		{5, 1000, 200},
	}
	for _, c := range cases {
		lim := BuildIPRateLimiter(newAntiCC("rate", c.window, c.limit), "unit-test")
		if lim == nil {
			t.Fatalf("窗口%d/次数%d 构造出 nil", c.window, c.limit)
		}
		if got := float64(lim.RatePerSecond()); math.Abs(got-c.wantRate) > 1e-9 {
			t.Errorf("窗口%d秒/%d次：每秒速率应为 %.6f，实际 %.6f（是否又把窗口秒数当成速率了？）",
				c.window, c.limit, c.wantRate, got)
		}
		if lim.Burst() != c.limit {
			t.Errorf("窗口%d秒/%d次：突发额度应为 %d，实际 %d", c.window, c.limit, c.limit, lim.Burst())
		}
		if lim.IsWindowMode() {
			t.Errorf("limit_mode=rate 不应构造成滑动窗口模式")
		}
	}
}

func TestBuildIPRateLimiter_WindowModeUsesRateAsWindow(t *testing.T) {
	lim := BuildIPRateLimiter(newAntiCC("window", 60, 100), "unit-test")
	if lim == nil {
		t.Fatal("构造出 nil")
	}
	if !lim.IsWindowMode() {
		t.Fatal("limit_mode=window 应构造成滑动窗口模式")
	}
	if lim.WindowSeconds() != 60 {
		t.Errorf("时间窗口应为 60 秒，实际 %d", lim.WindowSeconds())
	}
	if lim.Burst() != 100 {
		t.Errorf("窗口内最大请求数应为 100，实际 %d", lim.Burst())
	}
}

func TestBuildIPRateLimiter_DisabledAndIllegalWindow(t *testing.T) {
	if lim := BuildIPRateLimiter(model.AntiCC{}, "unit-test"); lim != nil {
		t.Error("未配置CC防护(Id为空)时应返回 nil")
	}
	// 窗口为 0 会导致除零/窗口退化，必须兜底而不是静默失效
	lim := BuildIPRateLimiter(newAntiCC("rate", 0, 100), "unit-test")
	if lim == nil {
		t.Fatal("非法窗口应兜底构造，而不是返回 nil")
	}
	if float64(lim.RatePerSecond()) <= 0 || math.IsInf(float64(lim.RatePerSecond()), 0) {
		t.Errorf("非法窗口兜底后速率应为有限正数，实际 %v", lim.RatePerSecond())
	}
}

// AST 护栏：除 anticc_limiter.go 外，本包任何地方都不得再直接 new 限流器。
// 直接构造就意味着又出现了第二份算法，B1 那类「两处不一致」的问题会重新长回来。
func TestNoDirectRateLimiterConstruction(t *testing.T) {
	const allowedFile = "anticc_limiter.go"
	banned := map[string]bool{"NewIPRateLimiter": true, "NewWindowIPRateLimiter": true}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), ".go") && !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("解析 wafenginecore 包失败: %v", err)
	}

	for _, pkg := range pkgs {
		for fileName, file := range pkg.Files {
			if strings.HasSuffix(fileName, allowedFile) {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !banned[sel.Sel.Name] {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok || pkgIdent.Name != "webplugin" {
					return true
				}
				t.Errorf("%s 第%d行直接调用了 webplugin.%s；"+
					"限流器必须统一由 BuildIPRateLimiter 构造，否则冷启动与热更新会再次算出不同阈值",
					fileName, fset.Position(call.Pos()).Line, sel.Sel.Name)
				return true
			})
		}
	}
}
