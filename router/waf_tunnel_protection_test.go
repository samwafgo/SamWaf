package router

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/middleware"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/spec"
	"SamWaf/wafsec"
	"encoding/json"
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

func TestTunnelProtectionRoutesRequireManagerAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name, role    string
		openAPI, auth bool
		want          int
	}{
		{name: "no session", auth: true, want: -999},
		{name: "security admin", role: enums.ROLE_SECURITY_ADMIN, want: -1},
		{name: "super admin", role: enums.ROLE_SUPER_ADMIN, want: -1},
		{name: "audit admin", role: enums.ROLE_AUDIT_ADMIN, want: -403},
		{name: "system admin", role: enums.ROLE_SYSTEM_ADMIN, want: -403},
		{name: "openapi", openAPI: true, want: -403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			group := r.Group("")
			if tc.auth {
				group.Use(middleware.Auth())
			} else {
				group.Use(func(c *gin.Context) {
					c.Set("userRole", tc.role)
					c.Set("is_openapi", tc.openAPI)
				})
			}
			new(WafTunnelRouter).InitWafTunnelRouter(group)
			for _, endpoint := range []string{"detail", "region", "ddns", "refresh"} {
				method := http.MethodPost
				if endpoint == "detail" {
					method = http.MethodGet
				}
				rec := httptest.NewRecorder()
				r.ServeHTTP(rec, httptest.NewRequest(method, "/api/v1/tunnel/tunnel/protection/"+endpoint, strings.NewReader("{}")))
				var reply struct{ Code int }
				if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil || reply.Code != tc.want {
					t.Fatalf("%s: %s, want code=%d (%v)", endpoint, rec.Body.String(), tc.want, err)
				}
			}
		})
	}
}

func TestTunnelProtectionConfigurationRoundTrip(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "tunnel.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		t.Cleanup(func() { _ = sqlDB.Close() })
	}
	if err := db.AutoMigrate(&model.Tunnel{}, &model.SecurityAuditLog{}); err != nil {
		t.Fatal(err)
	}
	oldDB, oldLog, oldChan := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB, global.GWAF_CHAN_COMMON_MSG
	oldTenant, oldUser := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB, global.GWAF_CHAN_COMMON_MSG = db, db, make(chan spec.ChanCommon, 8)
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "tunnel", "waf"
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB, global.GWAF_CHAN_COMMON_MSG = oldDB, oldLog, oldChan
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
	})
	if err := db.Create(&model.Tunnel{BaseOrm: baseorm.BaseOrm{Id: "tunnel-1", Tenant_ID: "tunnel", USER_CODE: "waf"}}).Error; err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	group := r.Group("", func(c *gin.Context) {
		c.Set("userRole", enums.ROLE_SUPER_ADMIN)
		c.Set("loginAccount", "operator")
	})
	new(WafTunnelRouter).InitWafTunnelRouter(group)

	call := func(method, path, body string, wantCode int, dst any) {
		t.Helper()
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(method, "/api/v1/tunnel/tunnel/protection/"+path, strings.NewReader(body)))
		var reply struct {
			Code int
			Data string
			Msg  string
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil || reply.Code != wantCode {
			t.Fatalf("%s: code=%d msg=%q, want code=%d (%v)", path, reply.Code, reply.Msg, wantCode, err)
		}
		if dst != nil {
			plain, err := wafsec.AesDecrypt(reply.Data, global.GWAF_COMMUNICATION_KEY)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(plain, dst); err != nil {
				t.Fatal(err)
			}
		}
	}
	call(http.MethodPost, "region", `{"id":"tunnel-1","revision":0,"enabled":true,"fallback":"allow","unknown":"deny","rules":[]}`, 0, nil)
	call(http.MethodPost, "ddns", `{"id":"tunnel-1","revision":0,"bindings":[{"domain":"Home.Example.NET.","family":"ipv4","enabled":true}]}`, 0, nil)
	var detail struct {
		Region          model.TunnelRegionProtection `json:"region"`
		DDNS            model.TunnelDDNSProtection   `json:"ddns"`
		States          []model.TunnelDDNSStatus     `json:"states"`
		WhitelistActive bool                         `json:"whitelist_active"`
	}
	call(http.MethodGet, "detail?id=tunnel-1", "", 0, &detail)
	if detail.Region.Revision != 1 || !detail.Region.Enabled || detail.Region.Unknown != "deny" || detail.DDNS.Revision != 1 || !detail.WhitelistActive || len(detail.DDNS.Bindings) != 1 || detail.DDNS.Bindings[0].Domain != "home.example.net" || len(detail.States) != 1 || detail.States[0].State != "pending" || detail.States[0].BindingID != detail.DDNS.Bindings[0].ID {
		t.Fatalf("unexpected protection detail: %+v", detail)
	}
	call(http.MethodPost, "ddns", `{"id":"tunnel-1","revision":1,"bindings":[]}`, -1, nil)
	call(http.MethodPost, "ddns", `{"id":"tunnel-1","revision":1,"bindings":[],"confirm_disable_whitelist":true}`, 0, nil)
	call(http.MethodGet, "detail?id=tunnel-1", "", 0, &detail)
	if detail.DDNS.Revision != 2 || detail.WhitelistActive || len(detail.DDNS.Bindings) != 0 || detail.Region.Revision != 1 {
		t.Fatalf("unexpected detail after removal: %+v", detail)
	}
	if got := len(global.GWAF_CHAN_COMMON_MSG); got != 3 {
		t.Fatalf("published %d changes, want 3", got)
	}
	var records []model.SecurityAuditLog
	if err := db.Where("object_type = ? AND object_id = ?", "tunnel", "tunnel-1").Order("create_time ASC").Find(&records).Error; err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("wrote %d audit records, want 3", len(records))
	}
	want := map[string]int{model.AuditEventConfigTunnelRegion: 1, model.AuditEventConfigTunnelDDNS: 2}
	for _, record := range records {
		want[record.Event]--
		if record.AccountName != "operator" || record.Category != "config" || len(record.Detail) == 0 {
			t.Fatalf("unexpected audit metadata: %+v", record)
		}
	}
	for event, remaining := range want {
		if remaining != 0 {
			t.Fatalf("unexpected audit event count: %s = %d", event, remaining)
		}
	}
}
