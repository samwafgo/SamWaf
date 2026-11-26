package middleware

import (
	"SamWaf/enums"
	"SamWaf/service/waf_service"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func setupRoutePolicyRouter(role string, isOpenApi bool, audits *[]waf_service.AuditEntry) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userRole", role)
		c.Set("loginAccount", "u1")
		if isOpenApi {
			c.Set("is_openapi", true)
		}
		c.Next()
	}, RoutePolicy())
	ok := func(c *gin.Context) { c.String(http.StatusOK, "reached") }
	r.POST("/api/v1/wafhost/host/list", ok)
	r.POST("/api/v1/wafhost/host/add", ok)
	r.POST("/api/v1/sslconfig/add", ok)
	r.POST("/api/v1/gpt/chat", ok)
	r.POST("/api/v1/unregistered/route", ok)
	return r
}

func TestRoutePolicyMiddleware(t *testing.T) {
	orig := routePolicyAudit
	defer func() { routePolicyAudit = orig }()

	cases := []struct {
		name    string
		role    string
		openapi bool
		path    string
		reached bool
	}{
		{"audit read", enums.ROLE_AUDIT_ADMIN, false, "/api/v1/wafhost/host/list", true},
		{"audit host add", enums.ROLE_AUDIT_ADMIN, false, "/api/v1/wafhost/host/add", false},
		{"audit write", enums.ROLE_AUDIT_ADMIN, false, "/api/v1/sslconfig/add", false},
		{"audit unregistered", enums.ROLE_AUDIT_ADMIN, false, "/api/v1/unregistered/route", false},
		{"system host add", enums.ROLE_SYSTEM_ADMIN, false, "/api/v1/wafhost/host/add", false},
		{"system write", enums.ROLE_SYSTEM_ADMIN, false, "/api/v1/sslconfig/add", true},
		{"system unregistered", enums.ROLE_SYSTEM_ADMIN, false, "/api/v1/unregistered/route", false},
		{"super unregistered", enums.ROLE_SUPER_ADMIN, false, "/api/v1/unregistered/route", true},
		{"audit gpt chat", enums.ROLE_AUDIT_ADMIN, false, "/api/v1/gpt/chat", false},
		{"system gpt chat", enums.ROLE_SYSTEM_ADMIN, false, "/api/v1/gpt/chat", true},
		{"security host add", enums.ROLE_SECURITY_ADMIN, false, "/api/v1/wafhost/host/add", true},
		{"super host add", enums.ROLE_SUPER_ADMIN, false, "/api/v1/wafhost/host/add", true},
		{"empty role host add", "", false, "/api/v1/wafhost/host/add", true},
		{"openapi host add", enums.ROLE_AUDIT_ADMIN, true, "/api/v1/wafhost/host/add", true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var audits []waf_service.AuditEntry
			routePolicyAudit = func(e waf_service.AuditEntry) { audits = append(audits, e) }
			r := setupRoutePolicyRouter(tt.role, tt.openapi, &audits)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, tt.path, nil))
			reached := w.Body.String() == "reached"
			if reached != tt.reached {
				t.Fatalf("reached=%v want=%v body=%q", reached, tt.reached, w.Body.String())
			}
			if !tt.reached && (len(audits) != 1 || audits[0].AccountName != "u1" || audits[0].URL != "POST "+tt.path) {
				t.Fatalf("denied request audit = %+v", audits)
			}
			if tt.reached && len(audits) != 0 {
				t.Fatalf("allowed request should not audit: %+v", audits)
			}
		})
	}
}
