package waf_service

// 护栏：给 model.Hosts 加一个站点级可配置字段时，很容易只改了结构体、迁移和引擎，
// 却忘了同步 WafHostAddReq/WafHostEditReq 和 service 的写入路径。
// 那样 gin 会静默丢弃前端传来的字段，接口照常返回"保存成功"，值却根本没进库
// —— 真实IP来源加固的 5 个字段(ip_source_mode/ip_real_header/ip_trust_proxies/
// ip_trust_depth/cdn_provider)就是这么漏掉的，表现为"选了指定HTTP头保存成功，
// 下次打开还是默认取 XFF"。这里用 AST 静态兜住，不依赖跑起来才发现。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// hostFieldSyncExempt 不经过站点编辑表单的字段(内部/运行态/由独立接口维护)。
// 新增豁免必须在这里写明理由，避免这张表变成"忘了同步就往里塞"的垃圾桶。
var hostFieldSyncExempt = map[string]string{
	"Code":         "新增时由后端生成；编辑时作为 where 条件而非更新列",
	"GUARD_STATUS": "由 ModifyGuardStatusApi 单独维护",
	"GLOBAL_HOST":  "全局站点标记，内部维护不开放编辑",
}

// parseGoFile 解析源码文件为 AST
func parseGoFile(t *testing.T, path string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("解析 %s 失败: %v", path, err)
	}
	return f
}

// structFieldNames 取某个结构体的具名字段(嵌入字段无 Names，自动跳过)
func structFieldNames(t *testing.T, file *ast.File, structName string) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != structName {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range st.Fields.List {
			for _, name := range field.Names {
				names[name.Name] = true
			}
		}
		return false
	})
	if len(names) == 0 {
		t.Fatalf("结构体 %s 未找到或没有具名字段", structName)
	}
	return names
}

// funcCompositeKeys 收集某个方法体内所有复合字面量的 key：
// 结构体字面量取标识符名(如 IPMode:)，map 字面量取字符串键(如 "IPMode":)。
func funcCompositeKeys(t *testing.T, file *ast.File, funcName string) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != funcName {
			return true
		}
		found = true
		ast.Inspect(fd.Body, func(inner ast.Node) bool {
			kv, ok := inner.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			switch k := kv.Key.(type) {
			case *ast.Ident:
				keys[k.Name] = true
			case *ast.BasicLit:
				if k.Kind == token.STRING {
					if s, err := strconv.Unquote(k.Value); err == nil {
						keys[s] = true
					}
				}
			}
			return true
		})
		return false
	})
	if !found {
		t.Fatalf("方法 %s 未找到", funcName)
	}
	return keys
}

// TestHostFieldsReachRequestAndService 断言 model.Hosts 的每个可配置字段都完整走通
// 「请求结构体 → service 写入」这条链路，任一环缺失都会让配置静默丢失。
func TestHostFieldsReachRequestAndService(t *testing.T) {
	hostFields := structFieldNames(t, parseGoFile(t, "../../model/hosts.go"), "Hosts")

	reqFile := parseGoFile(t, "../../model/request/waf_host_req.go")
	addReq := structFieldNames(t, reqFile, "WafHostAddReq")
	editReq := structFieldNames(t, reqFile, "WafHostEditReq")

	svcFile := parseGoFile(t, "waf_host.go")
	addWrite := funcCompositeKeys(t, svcFile, "AddApi")
	editWrite := funcCompositeKeys(t, svcFile, "ModifyApi")

	for field := range hostFields {
		if _, exempt := hostFieldSyncExempt[field]; exempt {
			continue
		}

		if !addReq[field] {
			t.Errorf("model.Hosts.%s 没有出现在 WafHostAddReq，新增时会被 gin 静默丢弃"+
				"（若确实不该走表单，请加进 hostFieldSyncExempt 并写明理由）", field)
		} else if !addWrite[field] {
			t.Errorf("WafHostAddReq.%s 没有写进 WafHostService.AddApi 的 model.Hosts 字面量，新增时值不会入库", field)
		}

		if !editReq[field] {
			t.Errorf("model.Hosts.%s 没有出现在 WafHostEditReq，编辑时会被 gin 静默丢弃"+
				"（若确实不该走表单，请加进 hostFieldSyncExempt 并写明理由）", field)
		} else if !editWrite[field] {
			t.Errorf("WafHostEditReq.%s 没有写进 WafHostService.ModifyApi 的 hostMap，编辑时值不会入库", field)
		}
	}
}
