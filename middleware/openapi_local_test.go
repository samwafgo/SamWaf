package middleware

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafsec"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestIsDirectLoopbackRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldHeader := global.GCONFIG_MANAGE_PROXY_HEADER
	global.GCONFIG_MANAGE_PROXY_HEADER = " , X-Client-IP , X-Origin-IP, "
	t.Cleanup(func() { global.GCONFIG_MANAGE_PROXY_HEADER = oldHeader })
	for _, tc := range []struct {
		name, remote string
		allowed      bool
	}{
		{"ipv4", "127.0.0.1:5000", true},
		{"ipv4_loopback_range", "127.0.0.2:5000", true},
		{"ipv6", "[::1]:5000", true},
		{"mapped_ipv4", "[::ffff:127.0.0.1]:5000", true},
		{"private", "192.168.1.5:5000", false},
		{"public", "198.51.100.5:5000", false},
		{"ipv6_remote", "[2001:db8::1]:5000", false},
		{"malformed", "invalid", false},
		{"missing_port", "127.0.0.1", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			c.Request.RemoteAddr = tc.remote
			if got := isDirectLoopbackRequest(c); got != tc.allowed {
				t.Fatalf("loopback check = %v, want %v", got, tc.allowed)
			}
		})
	}
	for _, header := range []string{
		"X-Forwarded-For", "X-Real-IP", "Forwarded", "X-Forwarded-Host",
		"X-Client-IP", "X-Origin-IP", "x-forwarded-for", "fOrWaRdEd", "x-cLiEnT-iP",
	} {
		for _, value := range []string{"198.51.100.5", "127.0.0.1", ""} {
			t.Run(header+"/"+value, func(t *testing.T) {
				c, _ := gin.CreateTestContext(httptest.NewRecorder())
				c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
				c.Request.RemoteAddr = "127.0.0.1:5000"
				c.Request.Header[header] = []string{value}
				if isDirectLoopbackRequest(c) {
					t.Fatal("request with forwarding header was accepted")
				}
			})
		}
		t.Run(header+"/nil", func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
			c.Request.RemoteAddr = "[::1]:5000"
			c.Request.Header[header] = nil
			if isDirectLoopbackRequest(c) {
				t.Fatal("request with header key present was accepted")
			}
		})
	}
	t.Run("unrelated_header", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.RemoteAddr = "127.0.0.1:5000"
		c.Request.Header.Set("Content-Type", "application/json")
		if !isDirectLoopbackRequest(c) {
			t.Fatal("unrelated header prevented loopback access")
		}
	})
}

func openApiLocalTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "openapi.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.OPlatformKey{}); err != nil {
		t.Fatal(err)
	}
	oldDB := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = db
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB = oldDB
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	})
	return db
}

func TestValidateOpenApiKeyLocalOnly(t *testing.T) {
	db := openApiLocalTestDB(t)
	oldSwitch, oldHeader, oldLegacy := global.GCONFIG_OPEN_PLATFORM_ENABLED, global.GCONFIG_MANAGE_PROXY_HEADER, global.GCONFIG_COMM_LEGACY_KEY
	global.GCONFIG_MANAGE_PROXY_HEADER = " X-Client-IP, X-Origin-IP "
	global.GCONFIG_COMM_LEGACY_KEY = false
	t.Cleanup(func() {
		global.GCONFIG_OPEN_PLATFORM_ENABLED, global.GCONFIG_MANAGE_PROXY_HEADER, global.GCONFIG_COMM_LEGACY_KEY = oldSwitch, oldHeader, oldLegacy
	})
	if err := wafsec.InitCommKey(t.TempDir(), ""); err != nil {
		t.Fatal(err)
	}
	if !wafsec.CommKeyReady() {
		t.Fatal("transport key is not ready")
	}
	past := time.Now().UTC().Add(-time.Hour).Format("2006-01-02 15:04:05")
	future := time.Now().UTC().Add(time.Hour).Format("2006-01-02 15:04:05")
	for _, tc := range []struct {
		name                              string
		localOnly, status, enabled        int
		remote, header, expiry, whitelist string
		rateLimit                         int64
		missing                           bool
		wantMessage                       string
	}{
		{name: "local_switch_off", localOnly: 1, status: 1, remote: "127.0.0.1:5000"},
		{name: "local_switch_on_ipv6", localOnly: 1, status: 1, enabled: 1, remote: "[::1]:5000"},
		{name: "local_future_expiry", localOnly: 1, status: 1, remote: "127.0.0.1:5000", expiry: future},
		{name: "local_disabled", localOnly: 1, remote: "127.0.0.1:5000", wantMessage: "API Key 已禁用"},
		{name: "local_expired", localOnly: 1, status: 1, remote: "127.0.0.1:5000", expiry: past, wantMessage: "API Key 已过期"},
		{name: "local_remote", localOnly: 1, status: 1, remote: "192.168.1.5:5000", wantMessage: "该 API Key 仅允许本机调用"},
		{name: "local_invalid_peer", localOnly: 1, status: 1, remote: "invalid", wantMessage: "该 API Key 仅允许本机调用"},
		{name: "local_empty_forwarded", localOnly: 1, status: 1, remote: "127.0.0.1:5000", header: "fOrWaRdEd", wantMessage: "该 API Key 仅允许本机调用"},
		{name: "local_empty_custom", localOnly: 1, status: 1, remote: "127.0.0.1:5000", header: "x-cLiEnT-iP", wantMessage: "该 API Key 仅允许本机调用"},
		{name: "local_whitelist_denied", localOnly: 1, status: 1, remote: "127.0.0.1:5000", whitelist: "192.168.0.0/16", wantMessage: "IP 不在白名单中"},
		{name: "local_whitelist_allowed", localOnly: 1, status: 1, remote: "127.0.0.1:5000", whitelist: "127.0.0.0/8"},
		{name: "local_rate_limit", localOnly: 1, status: 1, remote: "127.0.0.1:5000", rateLimit: 1},
		{name: "normal_switch_off", status: 1, remote: "127.0.0.1:5000", wantMessage: "开放平台已关闭"},
		{name: "other_flag_switch_off", localOnly: 2, status: 1, remote: "127.0.0.1:5000", wantMessage: "开放平台已关闭"},
		{name: "normal_remote", status: 1, enabled: 1, remote: "198.51.100.5:5000"},
		{name: "normal_forwarded", status: 1, enabled: 1, remote: "127.0.0.1:5000", header: "Forwarded"},
		{name: "normal_disabled", enabled: 1, remote: "198.51.100.5:5000", wantMessage: "API Key 已禁用"},
		{name: "normal_expired", status: 1, enabled: 1, remote: "198.51.100.5:5000", expiry: past, wantMessage: "API Key 已过期"},
		{name: "normal_future_expiry", status: 1, enabled: 1, remote: "198.51.100.5:5000", expiry: future},
		{name: "normal_whitelist_denied", status: 1, enabled: 1, remote: "198.51.100.5:5000", whitelist: "127.0.0.1", wantMessage: "IP 不在白名单中"},
		{name: "normal_rate_limit", status: 1, enabled: 1, remote: "198.51.100.5:5000", rateLimit: 1},
		{name: "missing_switch_off", missing: true, remote: "127.0.0.1:5000", wantMessage: "开放平台已关闭"},
		{name: "missing_switch_on", missing: true, enabled: 1, remote: "127.0.0.1:5000", wantMessage: "无效的 API Key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			global.GCONFIG_OPEN_PLATFORM_ENABLED = int64(tc.enabled)
			apiKey, id := "not-a-valid-key", ""
			if !tc.missing {
				var err error
				id, apiKey, err = openApiKeyService.AddApi(request.WafOPlatformKeyAddReq{
					KeyName: tc.name, ExpireTime: tc.expiry, IPWhitelist: tc.whitelist, RateLimit: tc.rateLimit,
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := db.Model(&model.OPlatformKey{}).Where("id = ?", id).Updates(map[string]interface{}{"local_only": tc.localOnly, "status": tc.status}).Error; err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { rateLimitMap.Delete(id) })
			}
			reached := false
			r := gin.New()
			r.GET("/test", Auth(), func(c *gin.Context) {
				reached = true
				if c.GetString("openapi_key_id") != id || c.GetString("openapi_key_name") != tc.name || c.GetBool("openapi_local_only") != (tc.localOnly == 1) {
					t.Error("validated key context did not match")
				}
				response.OkWithData(map[string]bool{"accepted": true}, c)
			})
			call := func(wantCode int, wantMessage string, wantReached bool) {
				t.Helper()
				reached = false
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				req.RemoteAddr = tc.remote
				req.Header.Set("X-API-Key", apiKey)
				if tc.header != "" {
					req.Header[tc.header] = []string{""}
				}
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				var result struct {
					Code int                    `json:"code"`
					Msg  string                 `json:"msg"`
					Data map[string]interface{} `json:"data"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatalf("expected plain JSON result: %v", err)
				}
				if w.Code != http.StatusOK || result.Code != wantCode || reached != wantReached || (wantMessage != "" && result.Msg != wantMessage) {
					t.Fatalf("HTTP=%d code=%d msg=%q reached=%v; want code=%d msg=%q reached=%v", w.Code, result.Code, result.Msg, reached, wantCode, wantMessage, wantReached)
				}
			}
			if tc.wantMessage != "" {
				call(response.AUTHFAIL, tc.wantMessage, false)
			} else {
				call(response.SUCCESS, "", true)
				if tc.rateLimit > 0 {
					call(response.ERROR, "请求频率超限，请稍后再试", false)
				}
			}
		})
	}
}

func TestOpenApiLogBodyPolicies(t *testing.T) {
	db := openApiLocalTestDB(t)
	if err := db.AutoMigrate(&model.OPlatformLog{}); err != nil {
		t.Fatal(err)
	}
	oldLogDB := global.GWAF_LOCAL_LOG_DB
	global.GWAF_LOCAL_LOG_DB = db
	t.Cleanup(func() { global.GWAF_LOCAL_LOG_DB = oldLogDB })
	id, _, err := openApiKeyService.AddApi(request.WafOPlatformKeyAddReq{KeyName: "log-test"})
	if err != nil {
		t.Fatal(err)
	}
	logged, counted := make(chan struct{}, 1), make(chan struct{}, 1)
	if err := db.Callback().Create().After("gorm:commit_or_rollback_transaction").Register("openapi_test_log_done", func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Table == "o_platform_logs" {
			logged <- struct{}{}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Callback().Raw().After("gorm:raw").Register("openapi_test_count_done", func(tx *gorm.DB) {
		counted <- struct{}{}
	}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, path              string
		localOnly               bool
		omitRequestBody         bool
		omitResponseBody        bool
		containsSensitiveResult bool
	}{
		{name: "local", path: "/api/v1/wafhost/host/local", localOnly: true, omitRequestBody: true, omitResponseBody: true},
		{name: "site_add", path: "/api/v1/wafhost/host/add", omitRequestBody: true, omitResponseBody: true},
		{name: "site_edit", path: "/api/v1/wafhost/host/edit", omitRequestBody: true, omitResponseBody: true},
		{name: "site_detail", path: "/api/v1/wafhost/host/detail", omitResponseBody: true, containsSensitiveResult: true},
		{name: "site_list", path: "/api/v1/wafhost/host/list", omitResponseBody: true, containsSensitiveResult: true},
		{name: "ordinary", path: "/api/v1/other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"label":"example"}`
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("is_openapi", true)
				c.Set("openapi_key_id", id)
				c.Set("openapi_key_name", "log-test")
				c.Set("openapi_local_only", tc.localOnly)
				c.Next()
			})
			method := http.MethodPost
			if strings.HasSuffix(tc.path, "/detail") {
				method = http.MethodGet
			}
			r.Handle(method, tc.path, OpenApiLogMiddleware(), func(c *gin.Context) {
				data, err := c.GetRawData()
				if err != nil || string(data) != body {
					t.Error("handler did not receive the complete request body")
				}
				if tc.containsSensitiveResult {
					response.OkWithData(map[string]string{"keyfile": "log-test-sensitive-marker", "custom_headers": "log-test-sensitive-marker"}, c)
				} else {
					response.OkWithData(map[string]bool{"accepted": true}, c)
				}
			})
			req := httptest.NewRequest(method, tc.path, strings.NewReader(body))
			req.RemoteAddr = "127.0.0.1:5000"
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusOK || (tc.containsSensitiveResult && !strings.Contains(w.Body.String(), "log-test-sensitive-marker")) {
				t.Fatal("HTTP result did not preserve the actual response")
			}
			for _, done := range []chan struct{}{logged, counted} {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("asynchronous OpenAPI logging did not complete")
				}
			}
			var entry model.OPlatformLog
			if err := db.Where("request_path = ?", tc.path).First(&entry).Error; err != nil {
				t.Fatal(err)
			}
			wantRequestBody := body
			if tc.omitRequestBody {
				wantRequestBody = ""
			}
			if entry.RequestBody != wantRequestBody || entry.RequestMethod != method || entry.StatusCode != http.StatusOK || entry.TimeStr == "" {
				t.Fatal("OpenAPI log did not preserve expected request policy and result metadata")
			}
			if tc.omitResponseBody {
				if entry.ResponseBody != "" || strings.Contains(entry.ResponseBody, "log-test-sensitive-marker") {
					t.Fatal("OpenAPI response policy did not omit the logged response")
				}
			} else {
				if !strings.Contains(entry.ResponseBody, `"code":0`) {
					t.Fatal("OpenAPI log did not preserve the permitted result code")
				}
				if tc.containsSensitiveResult && !strings.Contains(entry.ResponseBody, "log-test-sensitive-marker") {
					t.Fatal("OpenAPI log did not preserve the permitted response")
				}
			}
		})
	}
}

func TestOpenApiLocalOnlyMigration(t *testing.T) {
	var oldDialect dialect.DBDialect
	func() {
		defer func() { _ = recover() }()
		oldDialect = dialect.Get()
	}()
	dialect.Register(&dialect.SQLiteDialect{})
	t.Cleanup(func() { dialect.Register(oldDialect) })
	db := openApiLocalTestDB(t)
	if err := wafdb.RunCoreDBMigrations(db); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ordinary", "local"} {
		if _, _, err := openApiKeyService.AddApi(request.WafOPlatformKeyAddReq{KeyName: name}); err != nil {
			t.Fatal(err)
		}
	}
	migrationID := "202611040001_add_oplatform_key_local_only"
	removeMigrationRecord := func() {
		t.Helper()
		var record struct{ ID string }
		if err := db.Table("migrations").Where("id = ?", migrationID).Delete(&record).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Migrator().DropColumn(&model.OPlatformKey{}, "LocalOnly"); err != nil {
		t.Fatal(err)
	}
	removeMigrationRecord()
	if err := wafdb.RunCoreDBMigrations(db); err != nil {
		t.Fatal(err)
	}
	var rows []model.OPlatformKey
	if err := db.Find(&rows).Error; err != nil || len(rows) != 2 {
		t.Fatalf("upgraded rows: count=%d error=%v", len(rows), err)
	}
	for _, row := range rows {
		if row.LocalOnly != 0 {
			t.Fatal("existing key did not remain ordinary")
		}
	}
	if err := db.Model(&model.OPlatformKey{}).Where("key_name = ?", "local").Update("local_only", 1).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.OPlatformKey{}).Where("key_name = ?", "ordinary").Update("local_only", nil).Error; err != nil {
		t.Fatal(err)
	}
	removeMigrationRecord()
	for i := 0; i < 2; i++ {
		if err := wafdb.RunCoreDBMigrations(db); err != nil {
			t.Fatal(err)
		}
	}
	var nulls int64
	if err := db.Model(&model.OPlatformKey{}).Where("local_only IS NULL").Count(&nulls).Error; err != nil || nulls != 0 {
		t.Fatalf("NULL backfill: count=%d error=%v", nulls, err)
	}
	var local model.OPlatformKey
	if err := db.Where("key_name = ?", "local").First(&local).Error; err != nil || local.LocalOnly != 1 {
		t.Fatal("migration did not preserve an existing local key")
	}
}
