package middleware

import (
	"SamWaf/global"
	"SamWaf/model"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type appOpUnreadBody struct{ reads int }

func (b *appOpUnreadBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *appOpUnreadBody) Close() error             { return nil }

func TestAppOpPasswordAudit(t *testing.T) {
	for _, tc := range []struct {
		name, expected, provided, reason string
		allowed                          bool
	}{
		{"unset", "", "provided-secret-sentinel", "operation_credential_unset", false},
		{"mismatch", "configured-secret-sentinel", "provided-secret-sentinel", "operation_credential_mismatch", false},
		{"accepted", "configured-secret-sentinel", "configured-secret-sentinel", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "audit.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.AutoMigrate(&model.SecurityAuditLog{}); err != nil {
				t.Fatal(err)
			}
			oldLog, oldPassword, oldHeader := global.GWAF_LOCAL_LOG_DB, global.GWAF_APP_OP_PASSWORD, global.GCONFIG_MANAGE_PROXY_HEADER
			oldUser, oldTenant := global.GWAF_USER_CODE, global.GWAF_TENANT_ID
			global.GWAF_LOCAL_LOG_DB, global.GWAF_APP_OP_PASSWORD, global.GCONFIG_MANAGE_PROXY_HEADER = db, tc.expected, ""
			global.GWAF_USER_CODE, global.GWAF_TENANT_ID = "audit-user", "audit-tenant"
			t.Cleanup(func() {
				global.GWAF_LOCAL_LOG_DB, global.GWAF_APP_OP_PASSWORD, global.GCONFIG_MANAGE_PROXY_HEADER = oldLog, oldPassword, oldHeader
				global.GWAF_USER_CODE, global.GWAF_TENANT_ID = oldUser, oldTenant
				sqlDB, _ := db.DB()
				_ = sqlDB.Close()
			})
			body := &appOpUnreadBody{}
			req := httptest.NewRequest(http.MethodPost, "/app/upload?token=query-secret-sentinel", nil)
			req.Body = body
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set("Content-Type", "multipart/form-data; boundary=unused")
			req.Header.Set("X-App-Op-Password", tc.provided)
			req.Header.Set("X-Forwarded-For", "198.51.100.1")
			req.Header.Set("Authorization", "header-secret-sentinel")
			r := gin.New()
			called := false
			r.Use(func(c *gin.Context) { c.Set("loginAccount", "audit-operator"); c.Next() })
			r.POST("/app/upload", AppOpPasswordRequired(), func(c *gin.Context) { called = true; c.Status(http.StatusNoContent) })
			response := httptest.NewRecorder()
			r.ServeHTTP(response, req)
			if body.reads != 0 {
				t.Fatalf("middleware read multipart body %d times", body.reads)
			}
			var rows []model.SecurityAuditLog
			if err := db.Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			if tc.allowed {
				if !called || response.Code != http.StatusNoContent || len(rows) != 0 {
					t.Fatalf("accepted called=%v status=%d rows=%d", called, response.Code, len(rows))
				}
				return
			}
			if called || response.Code != http.StatusUnauthorized || len(rows) != 1 {
				t.Fatalf("denied called=%v status=%d rows=%d", called, response.Code, len(rows))
			}
			row := rows[0]
			if row.Event != model.AuditEventAppOpDenied || row.Category != model.AuditCategoryApp || row.Result != model.AccessAuditFail || row.AccountName != "audit-operator" || row.ClientIP != "127.0.0.1" || row.URL != "/app/upload" || !strings.Contains(row.Message, tc.reason) || row.Host != "" || row.HostCode != "" || row.UserAgent != "" {
				t.Fatalf("unexpected denial audit: %+v", row)
			}
			encoded, _ := json.Marshal(row)
			if strings.Contains(string(encoded), "secret-sentinel") {
				t.Fatalf("audit contains a sensitive marker: %s", encoded)
			}
			if model.AccessEventName(row.Event) == row.Event {
				t.Fatal("missing event name")
			}
		})
	}
}
