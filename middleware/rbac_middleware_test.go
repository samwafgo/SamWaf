package middleware

import (
	"SamWaf/enums"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// setupRBACRouter 构造一个最小路由：先注入 userRole/is_openapi，再挂 RequireRole，
// 终端 handler 写出 "reached"。据此判断请求是否被放行。
func setupRBACRouter(userRole string, isOpenApi bool, allowed ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if userRole != "" {
			c.Set("userRole", userRole)
		}
		if isOpenApi {
			c.Set("is_openapi", true)
		}
		c.Next()
	})
	r.GET("/t", RequireRole(allowed...), func(c *gin.Context) {
		c.String(http.StatusOK, "reached")
	})
	return r
}

func TestRequireRole(t *testing.T) {
	cases := []struct {
		name        string
		role        string
		openapi     bool
		allowed     []string
		wantReached bool
	}{
		{"super always allowed", enums.ROLE_SUPER_ADMIN, false, []string{enums.ROLE_SECURITY_ADMIN}, true},
		{"empty role falls back to super", "", false, []string{enums.ROLE_SECURITY_ADMIN}, true},
		{"invalid role falls back to super", "garbage", false, []string{enums.ROLE_SECURITY_ADMIN}, true},
		{"matching role allowed", enums.ROLE_SECURITY_ADMIN, false, []string{enums.ROLE_SECURITY_ADMIN}, true},
		{"non-matching role denied", enums.ROLE_AUDIT_ADMIN, false, []string{enums.ROLE_SECURITY_ADMIN}, false},
		{"system admin denied on security route", enums.ROLE_SYSTEM_ADMIN, false, []string{enums.ROLE_SECURITY_ADMIN}, false},
		{"openapi bypass allowed", enums.ROLE_AUDIT_ADMIN, true, []string{enums.ROLE_SECURITY_ADMIN}, true},
		{"multi allowed list hit", enums.ROLE_SYSTEM_ADMIN, false, []string{enums.ROLE_SYSTEM_ADMIN, enums.ROLE_SECURITY_ADMIN}, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := setupRBACRouter(tt.role, tt.openapi, tt.allowed...)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/t", nil)
			r.ServeHTTP(w, req)
			reached := w.Body.String() == "reached"
			if reached != tt.wantReached {
				t.Errorf("reached=%v want=%v (body=%q)", reached, tt.wantReached, w.Body.String())
			}
		})
	}
}
