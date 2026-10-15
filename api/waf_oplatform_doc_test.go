package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

// 开放平台文档表里的 key 必须与 router/ 实际注册的 method+path 对得上。
// 历史上有 34 条写错（方法写成 POST、路径前缀停留在旧命名），外部调用方照文档调会直接 404。

func registeredRoutes(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "router", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("router 目录不可读: %v", err)
	}
	routes := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			method := sel.Sel.Name
			switch method {
			case "GET", "POST", "PUT", "DELETE", "PATCH":
			default:
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			path, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			routes[method+" "+path] = true
			return true
		})
	}
	return routes
}

func TestOPlatformDocEntriesMatchRoutes(t *testing.T) {
	routes := registeredRoutes(t)
	var missing []string
	for key := range routeDetailMap {
		if !routes[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("开放平台文档表里的 %d 条接口在 router/ 中不存在：%v", len(missing), missing)
	}
}

// GET 条目的参数示例必须是 ?query 形式：buildCurlExample 靠此前缀拼 curl，JSON 体在 GET 上不成立
func TestOPlatformDocGetEntriesUseQueryExample(t *testing.T) {
	var bad []string
	for key, detail := range routeDetailMap {
		if len(key) < 4 || key[:4] != "GET " {
			continue
		}
		if detail.ParamExample == "(无需参数)" {
			continue
		}
		if len(detail.ParamExample) == 0 || detail.ParamExample[0] != '?' {
			bad = append(bad, key)
		}
	}
	if len(bad) > 0 {
		t.Fatalf("以下 GET 条目的参数示例不是 query 形式：%v", bad)
	}
}
