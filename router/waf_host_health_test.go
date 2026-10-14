package router

import (
	"SamWaf/enums"
	"SamWaf/middleware"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHealthRouteAuthenticationAndRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Run("authentication", func(t *testing.T) {
		r := gin.New()
		group := r.Group("")
		group.Use(middleware.Auth())
		new(HostRouter).InitHostRouter(group)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/wafhost/host/health/test", nil))
		var reply struct {
			Code int `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		if reply.Code != -999 {
			t.Fatalf("unauthenticated response=%s", rec.Body.String())
		}
	})
	for _, test := range []struct {
		role string
		want int
	}{
		{enums.ROLE_SUPER_ADMIN, -1}, {enums.ROLE_SECURITY_ADMIN, -1},
		{enums.ROLE_SYSTEM_ADMIN, -403}, {enums.ROLE_AUDIT_ADMIN, -403},
	} {
		t.Run(test.role, func(t *testing.T) {
			r := gin.New()
			group := r.Group("")
			group.Use(func(c *gin.Context) { c.Set("userRole", test.role) })
			new(HostRouter).InitHostRouter(group)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/wafhost/host/health/test", nil))
			var reply struct {
				Code int `json:"code"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if reply.Code != test.want {
				t.Fatalf("response=%s want=%d", rec.Body.String(), test.want)
			}
		})
	}
}
