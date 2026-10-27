package router

import (
	"SamWaf/enums"
	"SamWaf/middleware"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestWebsiteDiagnosticRouteAuthenticationAndRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name, role    string
		auth, openAPI bool
		code          int
		message       string
	}{
		{name: "unauthenticated", auth: true, code: -999},
		{name: "super admin", role: enums.ROLE_SUPER_ADMIN, code: -1, message: "网站诊断参数解析失败"},
		{name: "security admin", role: enums.ROLE_SECURITY_ADMIN, code: -1, message: "网站诊断参数解析失败"},
		{name: "system admin", role: enums.ROLE_SYSTEM_ADMIN, code: -403, message: "当前账号角色无权访问该功能"},
		{name: "audit admin", role: enums.ROLE_AUDIT_ADMIN, code: -403, message: "当前账号角色无权访问该功能"},
		{name: "openapi", openAPI: true, code: -1, message: "诊断功能仅支持登录用户调用"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			group := r.Group("")
			if tc.auth {
				group.Use(middleware.Auth())
			} else {
				group.Use(func(c *gin.Context) {
					c.Set("userRole", tc.role)
					if tc.openAPI {
						c.Set("is_openapi", true)
					}
				})
			}
			new(HostRouter).InitHostRouter(group)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/wafhost/host/diagnostic", nil))
			var reply struct {
				Code int    `json:"code"`
				Msg  string `json:"msg"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if reply.Code != tc.code || (tc.message != "" && reply.Msg != tc.message) {
				t.Fatalf("response=%s, want code=%d message=%q", rec.Body.String(), tc.code, tc.message)
			}
		})
	}
}
