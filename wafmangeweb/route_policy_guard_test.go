package wafmangeweb

import (
	"SamWaf/enums"
	"SamWaf/middleware"
	"bytes"
	"os"
	"sort"
	"testing"

	"github.com/gin-gonic/gin"
)

func sharedRouteKeys(t *testing.T) []string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	registerSharedRoutes(r.Group(""))
	keys := make([]string, 0)
	for _, rt := range r.Routes() {
		keys = append(keys, rt.Method+" "+rt.Path)
	}
	sort.Strings(keys)
	return keys
}

// 共享组每条路由都必须在策略表里登记，表里也不能留已不存在的路由。
func TestRoutePolicyCoversSharedRoutes(t *testing.T) {
	keys := sharedRouteKeys(t)
	entries := middleware.RoutePolicyEntries()
	registered := make(map[string]bool, len(keys))
	for _, k := range keys {
		registered[k] = true
		if _, ok := entries[k]; !ok {
			t.Errorf("共享组路由未在 middleware/route_policy.go 登记: %s", k)
		}
	}
	for k := range entries {
		if !registered[k] {
			t.Errorf("策略表登记了共享组不存在的路由: %s", k)
		}
	}
}

// 审计管理员只能访问 read/self；系统管理员不能访问 security；安全管理员与超级管理员全部可访问。
func TestRoutePolicyRoleMatrix(t *testing.T) {
	for _, k := range sharedRouteKeys(t) {
		rc := middleware.RoutePolicyEntries()[k]
		readOnly := rc == middleware.RouteClassRead || rc == middleware.RouteClassSelf
		if got := middleware.RouteClassAllows(rc, enums.ROLE_AUDIT_ADMIN); got != readOnly {
			t.Errorf("auditAdmin %s (%s): allowed=%v", k, rc, got)
		}
		if got := middleware.RouteClassAllows(rc, enums.ROLE_SYSTEM_ADMIN); got != (rc == middleware.RouteClassWrite || rc == middleware.RouteClassRead || rc == middleware.RouteClassSelf || rc == middleware.RouteClassSystem) {
			t.Errorf("systemAdmin %s (%s): allowed=%v", k, rc, got)
		}
		if got := middleware.RouteClassAllows(rc, enums.ROLE_SECURITY_ADMIN); got != (rc != middleware.RouteClassSystem) {
			t.Errorf("securityAdmin %s (%s): allowed=%v", k, rc, got)
		}
		for _, role := range []string{enums.ROLE_SUPER_ADMIN, ""} {
			if !middleware.RouteClassAllows(rc, role) {
				t.Errorf("%q %s (%s) denied", role, k, rc)
			}
		}
	}
}

// 报告涉及的网站写接口必须落在 security 类。
func TestRoutePolicyHostWritesAreSecurity(t *testing.T) {
	entries := middleware.RoutePolicyEntries()
	for _, k := range []string{
		"POST /api/v1/wafhost/host/add",
		"POST /api/v1/wafhost/host/edit",
		"GET /api/v1/wafhost/host/del",
		"GET /api/v1/wafhost/host/guardstatus",
		"GET /api/v1/wafhost/host/startstatus",
		"POST /api/v1/wafhost/host/modfiyallstatus",
		"POST /api/v1/wafhost/pathrule/add",
		"POST /api/v1/wafhost/pathrule/edit",
		"GET /api/v1/wafhost/pathrule/del",
		"POST /api/v1/import",
	} {
		if entries[k] != middleware.RouteClassSecurity {
			t.Errorf("%s 应为 security，实际 %s", k, entries[k])
		}
	}
}

// 共享组必须真的挂上策略中间件；只看策略表测不到「忘了挂」。
func TestSharedGroupMountsRoutePolicy(t *testing.T) {
	server, err := os.ReadFile("localserver.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(server, []byte("sharedGroup.Use(middleware.RoutePolicy())")) {
		t.Fatal("共享组未挂载 RoutePolicy")
	}
	if !bytes.Contains(server, []byte("registerSharedRoutes(sharedGroup)")) {
		t.Fatal("共享组未走 registerSharedRoutes")
	}
}

// 会出网、生成文件或改运行态的接口不能落在 read/self 类。
func TestRoutePolicySideEffectRoutes(t *testing.T) {
	entries := middleware.RoutePolicyEntries()
	cases := map[string]middleware.RouteClass{
		"POST /api/v1/gpt/chat":                     middleware.RouteClassWrite,
		"POST /api/v1/samwaf/report/create":         middleware.RouteClassWrite,
		"POST /api/v1/waflog/exports":               middleware.RouteClassWrite,
		"GET /api/v1/sysinfo/update":                middleware.RouteClassSystem,
		"GET /api/v1/sysinfo/rollback":              middleware.RouteClassSystem,
		"GET /api/v1/resetWAF":                      middleware.RouteClassSystem,
		"POST /api/v1/vipconfig/updateIpWhitelist":  middleware.RouteClassSystem,
		"GET /api/v1/vipconfig/manageClientIpProbe": middleware.RouteClassSystem,
	}
	for k, want := range cases {
		if got := entries[k]; got != want {
			t.Errorf("%s 应为 %s，实际 %s", k, want, got)
		}
	}
}
