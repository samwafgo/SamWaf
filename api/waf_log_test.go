package api

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/service/waf_service"
	"SamWaf/wafdb/dialect"
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func setupLogAPITest(t *testing.T) *gorm.DB {
	t.Helper()
	priorDialect := func() (d dialect.DBDialect) {
		defer func() { _ = recover() }()
		return dialect.Get()
	}()
	dialect.Register(&dialect.SQLiteDialect{})
	db := openNotifyTestDB(t)
	if err := db.AutoMigrate(&model.ShareDb{}, &model.AccessLog{}, &model.SecurityEvent{}, &model.EventPayload{}, &innerbean.WebLog{}); err != nil {
		t.Fatal(err)
	}
	oldCore, oldLog := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB
	oldTenant, oldUser, oldChanging := global.GWAF_TENANT_ID, global.GWAF_USER_CODE, global.GDATA_CURRENT_CHANGE
	global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = db, db
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE, global.GDATA_CURRENT_CHANGE = "api-log-tenant", "api-log-user", false
	waf_service.InvalidateShardCounts()
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB = oldCore, oldLog
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE, global.GDATA_CURRENT_CHANGE = oldTenant, oldUser, oldChanging
		waf_service.InvalidateShardCounts()
		dialect.Register(priorDialect)
	})
	if err := db.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", func(d *gorm.DB) {
		d.Where("tenant_id = ? and user_code = ?", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
	}); err != nil {
		t.Fatal(err)
	}
	row := model.SecurityEvent{LogNarrow: model.LogNarrow{
		ReqUUID: "req_nonstandard_0", TenantId: global.GWAF_TENANT_ID, UserCode: global.GWAF_USER_CODE,
		URL: "https://example.test/check", Method: "GET", HostCode: "api-host", UNIX_ADD_TIME: 1,
	}}
	if err := db.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.AccessLog{LogNarrow: row.LogNarrow}).Error; err != nil {
		t.Fatal(err)
	}
	return db
}

func callLogTestAPI(t *testing.T, handler gin.HandlerFunc, method, target, body string) response.Response {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("is_openapi", true) })
	r.Handle(method, "/t", handler)
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var result response.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("response decode: %v, body=%s", err, rec.Body.String())
	}
	return result
}

func TestLogDetailAPIsHandleErrorsAndLegacyIDs(t *testing.T) {
	db := setupLogAPITest(t)
	api := &WafLogAPi{}
	for _, handler := range []struct {
		name string
		call gin.HandlerFunc
	}{{"detail", api.GetDetailApi}, {"copy", api.GetHttpCopyMaskApi}} {
		for _, format := range []string{"raw", "curl"} {
			for _, tc := range []struct {
				name, id, shard, wantMsg string
				wantCode                 int
			}{
				{"legacy-form", "req_nonstandard_0", "local_log.db", "获取成功", response.SUCCESS},
				{"trimmed", "  req_nonstandard_0  ", "local_log.db", "获取成功", response.SUCCESS},
				{"missing", "req_missing", "local_log.db", "未找到该识别码", response.ERROR},
				{"missing-auto", "req_missing", "auto", "未找到该识别码", response.ERROR},
				{"missing-shard", "req_missing", "local_log_199901.db", "存储已不存在", response.ERROR},
				{"empty", "", "local_log.db", "解析失败", response.ERROR},
				{"whitespace", "   ", "local_log.db", "格式不正确", response.ERROR},
				{"too-long", strings.Repeat("a", 65), "local_log.db", "解析失败", response.ERROR},
				{"invalid", "req_bad\nvalue", "local_log.db", "格式不正确", response.ERROR},
			} {
				t.Run(handler.name+"/"+format+"/"+tc.name, func(t *testing.T) {
					query := url.Values{"req_uuid": {tc.id}, "current_db_name": {tc.shard}, "output_format": {format}}
					got := callLogTestAPI(t, handler.call, http.MethodGet, "/t?"+query.Encode(), "")
					if got.Code != tc.wantCode || !strings.Contains(got.Msg, tc.wantMsg) {
						t.Fatalf("expected code=%d msg contains %q, got %+v", tc.wantCode, tc.wantMsg, got)
					}
					if got.Code != response.SUCCESS {
						data, ok := got.Data.(map[string]interface{})
						if !ok || len(data) != 0 {
							t.Fatalf("failure must not return empty detail or generated request: %+v", got.Data)
						}
					} else if handler.name == "detail" {
						data, ok := got.Data.(map[string]interface{})
						if !ok || data["req_uuid"] != "req_nonstandard_0" {
							t.Fatalf("req_uuid form binding failed: %+v", got.Data)
						}
					} else if data, ok := got.Data.(string); !ok || !strings.Contains(data, "GET") || strings.Contains(data, "curl -X  ") {
						t.Fatalf("copy should contain a populated request: %+v", got.Data)
					}
				})
			}
		}
	}
	if err := db.Callback().Query().Before("gorm:query").Register("test:read_error", func(db *gorm.DB) { db.AddError(errors.New("test read failure")) }); err != nil {
		t.Fatal(err)
	}
	for _, handler := range []gin.HandlerFunc{api.GetDetailApi, api.GetHttpCopyMaskApi} {
		got := callLogTestAPI(t, handler, http.MethodGet, "/t?req_uuid=req_nonstandard_0&current_db_name=local_log.db&output_format=curl", "")
		if got.Code != response.ERROR || !strings.Contains(got.Msg, "查询日志详情失败") {
			t.Fatalf("read failure must propagate: %+v", got)
		}
	}
}

func TestLogListAPIURLKeyword(t *testing.T) {
	db := setupLogAPITest(t)
	literal := "/api/a_b%20!x|z?q=中文"
	for _, table := range []string{model.AccessLogTableName, model.SecurityEventTableName} {
		if err := db.Table(table).Where("req_uuid = ?", "req_nonstandard_0").Update("url", literal).Error; err != nil {
			t.Fatal(err)
		}
	}
	api := &WafLogAPi{}
	for _, view := range []string{"access", "event"} {
		for _, tc := range []struct {
			name, keyword string
			wantCode      int
			wantTotal     float64
		}{
			{"empty", "", response.SUCCESS, 1},
			{"literal", "a_b%20!x|z?q=中文", response.SUCCESS, 1},
			{"unmatched", "/missing", response.SUCCESS, 0},
			{"max-characters", strings.Repeat("中", 2048), response.SUCCESS, 0},
			{"over-limit", strings.Repeat("中", 2049), response.ERROR, 0},
		} {
			t.Run(view+"/"+tc.name, func(t *testing.T) {
				body, err := json.Marshal(map[string]interface{}{
					"url_keyword": tc.keyword, "view_type": view, "current_db_name": "local_log.db",
					"unix_add_time_begin": "0", "unix_add_time_end": "10",
					"sort_by": "unix_add_time", "sort_descending": "desc", "pageIndex": 1, "pageSize": 10,
				})
				if err != nil {
					t.Fatal(err)
				}
				got := callLogTestAPI(t, api.GetListApi, http.MethodPost, "/t", string(body))
				if got.Code != tc.wantCode {
					t.Fatalf("expected code=%d, got %+v", tc.wantCode, got)
				}
				if got.Code == response.SUCCESS {
					data, ok := got.Data.(map[string]interface{})
					if !ok || data["total"] != tc.wantTotal {
						t.Fatalf("expected total=%v, got %+v", tc.wantTotal, got.Data)
					}
				}
			})
		}
	}
	got := callLogTestAPI(t, api.GetListApi, http.MethodPost, "/t", `{"url_keyword":123}`)
	if got.Code != response.ERROR {
		t.Fatalf("numeric URL keyword must fail binding: %+v", got)
	}
}

func TestLogListAPIUUIDValidationAndSelectedShard(t *testing.T) {
	setupLogAPITest(t)
	api := &WafLogAPi{}
	for _, tc := range []struct {
		name, id  string
		wantCode  int
		wantTotal float64
	}{
		{"legacy-trimmed", "  req_nonstandard_0  ", response.SUCCESS, 1},
		{"missing", "req_missing", response.SUCCESS, 0},
		{"too-long", strings.Repeat("a", 65), response.ERROR, 0},
		{"invalid", "req_bad value", response.ERROR, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]interface{}{
				"req_uuid": tc.id, "current_db_name": "local_log_199901.db",
				"unix_add_time_begin": "4102444800000", "unix_add_time_end": "4102531200000",
				"sort_by": "unix_add_time", "sort_descending": "desc", "pageIndex": 1, "pageSize": 10,
			})
			if err != nil {
				t.Fatal(err)
			}
			got := callLogTestAPI(t, api.GetListApi, http.MethodPost, "/t", string(body))
			if got.Code != tc.wantCode {
				t.Fatalf("expected code=%d got %+v", tc.wantCode, got)
			}
			if got.Code == response.SUCCESS {
				data, ok := got.Data.(map[string]interface{})
				if !ok || data["total"] != tc.wantTotal || data["uuid_lookup"] != true {
					t.Fatalf("selected shard/date UUID query: %+v", got.Data)
				}
			}
		})
	}
}
