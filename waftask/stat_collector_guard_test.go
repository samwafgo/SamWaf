package waftask

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// 护栏：日志聚合（CollectStatsFromLogs）绝不能再写 traffic_in / traffic_out。
//
// 背景：流量已改由引擎侧字节计量 + FlushTrafficStats 落库（issue #930）。
// 如果哪天有人"顺手"把 traffic 累加加回日志聚合里，两条路径会同时写同一列，
// 用户看到的流量会凭空翻倍，而且因为两边都"看起来是对的"，极难定位。
// 这里用 AST 检查（不看注释，避免误伤说明文字）把这条约束钉死。
func TestStatCollectorNoLongerWritesTraffic(t *testing.T) {
	const file = "stat_collector.go"

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0) // 不带 ParseComments：注释里提到 traffic 不算违规
	if err != nil {
		t.Fatalf("解析 %s 失败: %v", file, err)
	}

	banned := []string{"traffic_in", "traffic_out", "TrafficIn", "TrafficOut"}
	hit := func(s string) string {
		for _, b := range banned {
			if strings.Contains(s, b) {
				return b
			}
		}
		return ""
	}

	var violations []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.BasicLit:
			// SQL 列名 / gorm.Expr 里的字符串
			if v.Kind == token.STRING {
				if b := hit(v.Value); b != "" {
					violations = append(violations,
						fset.Position(v.Pos()).String()+" 出现字符串 "+b)
				}
			}
		case *ast.Ident:
			// 结构体字段 / 变量名
			if b := hit(v.Name); b != "" {
				violations = append(violations,
					fset.Position(v.Pos()).String()+" 出现标识符 "+b)
			}
		}
		return true
	})

	if len(violations) > 0 {
		t.Fatalf("%s 又开始写流量列了，会和引擎侧计量双计：\n  %s\n"+
			"流量只能由 waftask.FlushTrafficStats 写入，日志聚合只负责 count / time_spent。",
			file, strings.Join(violations, "\n  "))
	}
}

// 反向护栏：流量落库这条路径必须真的存在（防止被整体删掉后统计悄悄归零）
func TestTrafficFlushPathExists(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "task_traffic_stats.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 task_traffic_stats.go 失败: %v", err)
	}

	want := map[string]bool{
		"TaskTrafficFlush":   false, // 定时任务入口
		"FlushTrafficStats":  false, // 停机补刀也用它
		"writeTrafficStats":  false,
		"planTrafficUpserts": false,
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if _, exists := want[fn.Name.Name]; exists {
				want[fn.Name.Name] = true
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("流量落库链路缺少函数 %s —— 统计会静默归零", name)
		}
	}
}
