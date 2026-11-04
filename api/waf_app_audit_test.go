package api

import (
	"SamWaf/global"
	"SamWaf/globalobj"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/spec"
	"SamWaf/wafappengine"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupAppAuditTest(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	openDB := func(name string, tables ...interface{}) *gorm.DB {
		db, err := gorm.Open(sqlite.Open(filepath.Join(root, name)), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.AutoMigrate(tables...); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sqlDB, _ := db.DB(); _ = sqlDB.Close() })
		return db
	}
	core := openDB("core.db", &model.WafApp{}, &model.WafAppChangeLog{})
	log := openDB("log.db", &model.SecurityAuditLog{})
	oldCore, oldLog, oldDirs := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB, global.GWAF_APP_ALLOW_DIRS
	oldChan, oldEngine := global.GWAF_CHAN_COMMON_MSG, globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE
	oldHeader := global.GCONFIG_MANAGE_PROXY_HEADER
	oldUser, oldTenant := global.GWAF_USER_CODE, global.GWAF_TENANT_ID
	global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB, global.GWAF_APP_ALLOW_DIRS = core, log, root
	global.GWAF_CHAN_COMMON_MSG = make(chan spec.ChanCommon, 32)
	globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE = wafappengine.NewWafAppEngine()
	global.GCONFIG_MANAGE_PROXY_HEADER = ""
	global.GWAF_USER_CODE, global.GWAF_TENANT_ID = "app-audit-user", "app-audit-tenant"
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB, global.GWAF_LOCAL_LOG_DB, global.GWAF_APP_ALLOW_DIRS = oldCore, oldLog, oldDirs
		global.GWAF_CHAN_COMMON_MSG, globalobj.GWAF_RUNTIME_OBJ_APP_ENGINE = oldChan, oldEngine
		global.GCONFIG_MANAGE_PROXY_HEADER = oldHeader
		global.GWAF_USER_CODE, global.GWAF_TENANT_ID = oldUser, oldTenant
	})
	return root
}

func seedAppAuditApp(t *testing.T, root string) model.WafApp {
	t.Helper()
	app := model.WafApp{BaseOrm: baseorm.BaseOrm{Id: "audit-app-id"}, Code: "audit-app", Name: "审计应用", AppDir: filepath.Join(root, "app"), StartCmd: "unused-command", StartStatus: 1}
	if err := os.MkdirAll(app.AppDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := global.GWAF_LOCAL_DB.Create(&app).Error; err != nil {
		t.Fatal(err)
	}
	return app
}

func invokeAppAudit(t *testing.T, handler gin.HandlerFunc, req *http.Request) (*httptest.ResponseRecorder, model.SecurityAuditLog) {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = req
	ctx.Request.RemoteAddr = "127.0.0.1:43210"
	ctx.Request.Header.Set("X-Forwarded-For", "198.51.100.100")
	ctx.Request.Header.Set("Authorization", "header-secret-sentinel")
	ctx.Set("loginAccount", "audit-operator")
	ctx.Set("loginIP", "incorrect-login-ip")
	var before int64
	global.GWAF_LOCAL_LOG_DB.Model(&model.SecurityAuditLog{}).Count(&before)
	handler(ctx)
	var rows []model.SecurityAuditLog
	if err := global.GWAF_LOCAL_LOG_DB.Order("rowid").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if int64(len(rows)) != before+1 {
		t.Fatalf("audit rows=%d before=%d response=%s", len(rows), before, recorder.Body.String())
	}
	row := rows[len(rows)-1]
	if row.Category != model.AuditCategoryApp || row.AccountName != "audit-operator" || row.ClientIP != "127.0.0.1" || row.URL != req.URL.Path {
		t.Fatalf("unexpected audit attribution: %+v", row)
	}
	if row.Host != "" || row.HostCode != "" || row.UserAgent != "" || row.SessionCode != "" {
		t.Fatalf("unexpected website/header fields: %+v", row)
	}
	encoded, _ := json.Marshal(row)
	for _, secret := range []string{"header-secret-sentinel", "query-secret-sentinel", "env-secret-sentinel", "command-secret-sentinel", "body-secret-sentinel", "exception-secret-sentinel", "hash-secret-sentinel"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("audit contains sensitive marker %s", secret)
		}
	}
	if model.AccessEventName(row.Event) == row.Event {
		t.Fatalf("missing event name: %s", row.Event)
	}
	return recorder, row
}

func appJSONRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/app/op?token=query-secret-sentinel", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func appMultipartRequest(t *testing.T, filename, contents, hash string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("code", "audit-app")
	_ = writer.WriteField("hash", hash)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(part, contents)
	_ = writer.Close()
	r := httptest.NewRequest(http.MethodPost, "/app/file?token=query-secret-sentinel", &body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	return r
}

func TestAppAuditAddEditSummaries(t *testing.T) {
	root := setupAppAuditTest(t)
	api := &WafAppApi{}
	body := map[string]interface{}{"code": "audit-app", "name": "审计应用", "app_dir": filepath.Join(root, "app"), "start_cmd": "run command-secret-sentinel", "stop_cmd": "stop command-secret-sentinel", "env": "KEY=env-secret-sentinel"}
	encoded, _ := json.Marshal(body)
	_, row := invokeAppAudit(t, api.AddApi, appJSONRequest(string(encoded)))
	if row.Result != model.AccessAuditOK || row.Event != model.AuditEventAppAdd || !strings.Contains(row.Message, "stage=submitted") {
		t.Fatalf("unexpected add audit: %+v", row)
	}
	var app model.WafApp
	global.GWAF_LOCAL_DB.Where("code = ?", "audit-app").First(&app)
	body["id"] = app.Id
	body["start_cmd"], body["env"] = "new command-secret-sentinel", "KEY=new-env-secret-sentinel"
	encoded, _ = json.Marshal(body)
	_, row = invokeAppAudit(t, api.ModifyApi, appJSONRequest(string(encoded)))
	if row.Result != model.AccessAuditOK || row.Event != model.AuditEventAppEdit {
		t.Fatalf("unexpected edit audit: %+v", row)
	}
	var changes []model.WafAppChangeLog
	global.GWAF_LOCAL_DB.Order("rowid").Find(&changes)
	if len(changes) != 2 {
		t.Fatalf("change logs=%d", len(changes))
	}
	for _, log := range changes {
		var fields []appChange
		if err := json.Unmarshal([]byte(log.Changes), &fields); err != nil || len(fields) == 0 {
			t.Fatalf("changes must be a nonempty array: %s %v", log.Changes, err)
		}
		if strings.Contains(log.Changes, "secret-sentinel") || log.Operator != "audit-operator" || log.OperatorIP != "127.0.0.1" {
			t.Fatalf("unexpected change log: %+v", log)
		}
	}
	var addFields []appChange
	_ = json.Unmarshal([]byte(changes[0].Changes), &addFields)
	foundDir := false
	for _, f := range addFields {
		if f.Field == "app_dir" && f.New == app.AppDir && app.AppDir != "" {
			foundDir = true
		}
	}
	if !foundDir {
		t.Fatalf("add change log must keep the resolved work directory: %s", changes[0].Changes)
	}
	if len(global.GWAF_CHAN_COMMON_MSG) != 2 {
		t.Fatal("add/edit should submit without consuming or starting an application")
	}
}

func TestAppAuditFailures(t *testing.T) {
	for _, tc := range []struct {
		name, event, body, query, stage string
		handler                         func(*WafAppApi) gin.HandlerFunc
	}{
		{"add-bind", model.AuditEventAppAdd, `{"name":"body-secret-sentinel",`, "", "bind", func(a *WafAppApi) gin.HandlerFunc { return a.AddApi }},
		{"add-code", model.AuditEventAppAdd, `{"code":"../bad","name":"test","start_cmd":"command-secret-sentinel"}`, "", "validate", func(a *WafAppApi) gin.HandlerFunc { return a.AddApi }},
		{"add-env", model.AuditEventAppAdd, `{"code":"new-app","name":"test","start_cmd":"command-secret-sentinel","env":"env-secret-sentinel"}`, "", "save", func(a *WafAppApi) gin.HandlerFunc { return a.AddApi }},
		{"edit-bind", model.AuditEventAppEdit, `{`, "", "bind", func(a *WafAppApi) gin.HandlerFunc { return a.ModifyApi }},
		{"edit-missing", model.AuditEventAppEdit, `{"id":"missing","name":"test","start_cmd":"command-secret-sentinel"}`, "", "lookup", func(a *WafAppApi) gin.HandlerFunc { return a.ModifyApi }},
		{"delete-missing", model.AuditEventAppDel, "", "?id=missing", "lookup", func(a *WafAppApi) gin.HandlerFunc { return a.DelApi }},
		{"start-invalid", model.AuditEventAppStart, "", "?code=../bad", "validate", func(a *WafAppApi) gin.HandlerFunc { return a.StartApi }},
		{"stop-missing", model.AuditEventAppStop, "", "?code=missing", "lookup", func(a *WafAppApi) gin.HandlerFunc { return a.StopApi }},
		{"restart-missing", model.AuditEventAppRestart, "", "?code=missing", "lookup", func(a *WafAppApi) gin.HandlerFunc { return a.RestartApi }},
		{"clear-bind", model.AuditEventAppClearLogs, `{`, "", "bind", func(a *WafAppApi) gin.HandlerFunc { return a.ClearLogsApi }},
		{"upload-invalid", model.AuditEventAppUpload, `{`, "", "validate", func(a *WafAppApi) gin.HandlerFunc { return a.UploadFileApi }},
		{"upgrade-invalid", model.AuditEventAppUpgrade, `{`, "", "validate", func(a *WafAppApi) gin.HandlerFunc { return a.UpgradeApi }},
		{"rollback-invalid", model.AuditEventAppRollback, "", "?code=../bad", "validate", func(a *WafAppApi) gin.HandlerFunc { return a.RollbackApi }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupAppAuditTest(t)
			req := appJSONRequest(tc.body)
			if tc.query != "" {
				req = httptest.NewRequest(http.MethodPost, "/app/op"+tc.query+"&token=query-secret-sentinel", nil)
			}
			_, row := invokeAppAudit(t, tc.handler(&WafAppApi{}), req)
			if row.Result != model.AccessAuditFail || row.Event != tc.event || !strings.Contains(row.Message, "stage="+tc.stage+" ") {
				t.Fatalf("unexpected failure audit: %+v", row)
			}
		})
	}
}

func TestAppAuditSubmittedAndClearLogs(t *testing.T) {
	root := setupAppAuditTest(t)
	app := seedAppAuditApp(t, root)
	api := &WafAppApi{}
	for _, tc := range []struct {
		h            gin.HandlerFunc
		event, query string
	}{
		{api.StartApi, model.AuditEventAppStart, "?code=" + app.Code},
		{api.StopApi, model.AuditEventAppStop, "?code=" + app.Code},
		{api.RestartApi, model.AuditEventAppRestart, "?code=" + app.Code},
		{api.DelApi, model.AuditEventAppDel, "?id=" + app.Id},
	} {
		_, row := invokeAppAudit(t, tc.h, httptest.NewRequest(http.MethodPost, "/app/op"+tc.query+"&token=query-secret-sentinel", nil))
		if row.Event != tc.event || row.Result != model.AccessAuditOK || !strings.Contains(row.Message, "stage=submitted") || !strings.Contains(row.Message, app.Name) {
			t.Fatalf("unexpected submission: %+v", row)
		}
	}
	if len(global.GWAF_CHAN_COMMON_MSG) != 4 {
		t.Fatal("operations should only enqueue")
	}
	_, row := invokeAppAudit(t, api.ClearLogsApi, appJSONRequest(`{"code":"audit-app"}`))
	if row.Result != model.AccessAuditOK || row.Event != model.AuditEventAppClearLogs || !strings.Contains(row.Message, "stage=logs_cleared") {
		t.Fatalf("unexpected clear audit: %+v", row)
	}
}

func TestAppAuditUploadFirstOverwriteAndHashFailure(t *testing.T) {
	root := setupAppAuditTest(t)
	app := seedAppAuditApp(t, root)
	api := &WafAppApi{}
	for _, contents := range []string{"first body-secret-sentinel", "overwrite body-secret-sentinel"} {
		hash := sha256.Sum256([]byte(contents))
		_, row := invokeAppAudit(t, api.UploadFileApi, appMultipartRequest(t, "sample.bin", contents, hex.EncodeToString(hash[:])))
		if row.Result != model.AccessAuditOK || row.Event != model.AuditEventAppUpload || !strings.Contains(row.Message, "sample.bin") {
			t.Fatalf("unexpected upload audit: %+v", row)
		}
		got, err := os.ReadFile(filepath.Join(app.AppDir, "sample.bin"))
		if err != nil || string(got) != contents {
			t.Fatalf("file contents=%q err=%v", got, err)
		}
	}
	_, row := invokeAppAudit(t, api.UploadFileApi, appMultipartRequest(t, "sample.bin", "bad body-secret-sentinel", "hash-secret-sentinel"))
	if row.Result != model.AccessAuditFail || !strings.Contains(row.Message, "stage=upload_file") {
		t.Fatalf("unexpected hash failure: %+v", row)
	}
	got, _ := os.ReadFile(filepath.Join(app.AppDir, "sample.bin"))
	if string(got) != "overwrite body-secret-sentinel" {
		t.Fatal("hash failure changed original file")
	}
	var count int64
	global.GWAF_LOCAL_DB.Model(&model.WafAppChangeLog{}).Count(&count)
	if count != 2 {
		t.Fatalf("successful file changes=%d", count)
	}
}

type fakeAppAuditLifecycle struct {
	stopErr, startErr error
	stops, starts     int
}

func (f *fakeAppAuditLifecycle) StopApp(string) error  { f.stops++; return f.stopErr }
func (f *fakeAppAuditLifecycle) StartApp(string) error { f.starts++; return f.startErr }

func TestAppAuditUpgradeRollbackStages(t *testing.T) {
	for _, operation := range []string{"upgrade", "rollback"} {
		for _, outcome := range []string{"ok", "stop-fail", "file-fail", "file-and-start-fail", "start-fail"} {
			t.Run(operation+"/"+outcome, func(t *testing.T) {
				root := setupAppAuditTest(t)
				app := seedAppAuditApp(t, root)
				path := filepath.Join(app.AppDir, "sample.bin")
				if err := os.WriteFile(path, []byte("original"), 0700); err != nil {
					t.Fatal(err)
				}
				fake := &fakeAppAuditLifecycle{}
				if outcome == "stop-fail" {
					fake.stopErr = errors.New("exception-secret-sentinel")
				}
				if outcome == "start-fail" || outcome == "file-and-start-fail" {
					fake.startErr = errors.New("exception-secret-sentinel")
				}
				api := &WafAppApi{lifecycle: fake}
				fileFailure := outcome == "file-fail" || outcome == "file-and-start-fail"
				var req *http.Request
				var handler gin.HandlerFunc
				var event, stage string
				if operation == "upgrade" {
					hash := ""
					if fileFailure {
						hash = "hash-secret-sentinel"
					}
					req = appMultipartRequest(t, "sample.bin", "replacement body-secret-sentinel", hash)
					handler, event = api.UpgradeApi, model.AuditEventAppUpgrade
					stage = "file_replaced_restart_requested"
					if outcome == "start-fail" {
						stage = "file_replaced_restart_failed"
					}
					if fileFailure {
						stage = "replace_failed_restart_requested"
					}
					if outcome == "file-and-start-fail" {
						stage = "replace_failed_restart_failed"
					}
				} else {
					filename := "sample.bin.20261103120000"
					if !fileFailure {
						if err := os.MkdirAll(filepath.Join(app.AppDir, "backup"), 0755); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(app.AppDir, "backup", filename), []byte("replacement body-secret-sentinel"), 0700); err != nil {
							t.Fatal(err)
						}
					}
					req = httptest.NewRequest(http.MethodPost, "/app/rollback?code="+app.Code+"&filename="+url.QueryEscape(filename)+"&token=query-secret-sentinel", nil)
					handler, event = api.RollbackApi, model.AuditEventAppRollback
					stage = "file_restored_restart_requested"
					if outcome == "start-fail" {
						stage = "file_restored_restart_failed"
					}
					if fileFailure {
						stage = "restore_failed_restart_requested"
					}
					if outcome == "file-and-start-fail" {
						stage = "restore_failed_restart_failed"
					}
				}
				if outcome == "stop-fail" {
					stage = "stop"
				}
				recorder, row := invokeAppAudit(t, handler, req)
				wantResult := model.AccessAuditFail
				if outcome == "ok" {
					wantResult = model.AccessAuditOK
				}
				if row.Event != event || row.Result != wantResult || !strings.Contains(row.Message, "stage="+stage+" ") {
					t.Fatalf("unexpected operation audit: %+v", row)
				}
				wantStarts := 1
				if outcome == "stop-fail" {
					wantStarts = 0
				}
				if fake.stops != 1 || fake.starts != wantStarts {
					t.Fatalf("stops=%d starts=%d", fake.stops, fake.starts)
				}
				contents, _ := os.ReadFile(path)
				wantFile := "replacement body-secret-sentinel"
				if fileFailure || outcome == "stop-fail" {
					wantFile = "original"
				}
				if string(contents) != wantFile {
					t.Fatalf("file=%q want=%q", contents, wantFile)
				}
				var changes int64
				global.GWAF_LOCAL_DB.Model(&model.WafAppChangeLog{}).Count(&changes)
				wantChanges := int64(1)
				if fileFailure || outcome == "stop-fail" {
					wantChanges = 0
				}
				if changes != wantChanges {
					t.Fatalf("change logs=%d want=%d", changes, wantChanges)
				}
				if outcome == "ok" && (!strings.Contains(recorder.Body.String(), "查看运行状态") || strings.Contains(recorder.Body.String(), "已重新启动")) {
					t.Fatalf("response overstates runtime: %s", recorder.Body.String())
				}
			})
		}
	}
}

func TestAppAuditUpgradeRollbackDisabledApp(t *testing.T) {
	for _, operation := range []string{"upgrade", "rollback"} {
		for _, fileFailure := range []bool{false, true} {
			name := operation + "/ok"
			if fileFailure {
				name = operation + "/file-fail"
			}
			t.Run(name, func(t *testing.T) {
				root := setupAppAuditTest(t)
				app := seedAppAuditApp(t, root)
				if err := global.GWAF_LOCAL_DB.Model(&app).Update("start_status", 0).Error; err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(app.AppDir, "sample.bin"), []byte("original"), 0700); err != nil {
					t.Fatal(err)
				}
				fake := &fakeAppAuditLifecycle{}
				api := &WafAppApi{lifecycle: fake}
				var recorder *httptest.ResponseRecorder
				var row model.SecurityAuditLog
				stage := "file_replaced_app_disabled"
				if operation == "upgrade" {
					hash := ""
					if fileFailure {
						hash, stage = "bad-hash", "replace_failed_app_disabled"
					}
					recorder, row = invokeAppAudit(t, api.UpgradeApi, appMultipartRequest(t, "sample.bin", "replacement", hash))
				} else {
					filename := "sample.bin.20261103120000"
					stage = "file_restored_app_disabled"
					if fileFailure {
						stage = "restore_failed_app_disabled"
					} else {
						if err := os.MkdirAll(filepath.Join(app.AppDir, "backup"), 0755); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(app.AppDir, "backup", filename), []byte("replacement"), 0700); err != nil {
							t.Fatal(err)
						}
					}
					req := httptest.NewRequest(http.MethodPost, "/app/rollback?code="+app.Code+"&filename="+url.QueryEscape(filename), nil)
					recorder, row = invokeAppAudit(t, api.RollbackApi, req)
				}
				wantResult := model.AccessAuditOK
				if fileFailure {
					wantResult = model.AccessAuditFail
				}
				if row.Result != wantResult || !strings.Contains(row.Message, "stage="+stage+" ") {
					t.Fatalf("unexpected disabled-app audit: %+v", row)
				}
				if fake.stops != 1 || fake.starts != 0 {
					t.Fatalf("disabled app must not be started: stops=%d starts=%d", fake.stops, fake.starts)
				}
				if !fileFailure && !strings.Contains(recorder.Body.String(), "未启动") {
					t.Fatalf("response must say the app was not started: %s", recorder.Body.String())
				}
			})
		}
	}
}

func TestAppAuditFileChangeJSONEscaping(t *testing.T) {
	setupAppAuditTest(t)
	filename := `a"quoted.bin`
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/app/file", nil)
	ctx.Request.RemoteAddr = "127.0.0.1:1000"
	ctx.Set("loginAccount", "audit-operator")
	for _, operation := range []string{"上传", "升级", "回滚"} {
		recordAppFileChange(ctx, &appAudit{code: "audit-app", name: "test", filename: `../` + filename}, operation, operation+"文件")
	}
	var logs []model.WafAppChangeLog
	global.GWAF_LOCAL_DB.Find(&logs)
	if len(logs) != 3 {
		t.Fatalf("logs=%d", len(logs))
	}
	for _, log := range logs {
		var changes []appChange
		if err := json.Unmarshal([]byte(log.Changes), &changes); err != nil || len(changes) != 1 || changes[0].New != filename {
			t.Fatalf("invalid filename JSON: %s err=%v", log.Changes, err)
		}
	}
}
