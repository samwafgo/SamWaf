package middleware

import (
	"SamWaf/api"
	"SamWaf/cache"
	"SamWaf/common/gwebsocket"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafdb/dialect"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	gws "github.com/gorilla/websocket"
	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type sessionRetainedCache struct{ cache.CacheStore }

func (c *sessionRetainedCache) Remove(string) interface{} {
	return errors.New("cache remove unavailable")
}

func sessionFixture(t *testing.T) *gorm.DB {
	t.Helper()
	dialect.Register(&dialect.SQLiteDialect{})
	oldDB, oldCache := global.GWAF_LOCAL_DB, global.GCACHE_WAFCACHE
	oldTenant, oldUser := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	oldLegacy, oldRelease := global.GCONFIG_COMM_LEGACY_KEY, global.GWAF_RELEASE
	oldTTL, oldIP, oldFP, oldOTP := global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES, global.GCONFIG_ENABLE_STRICT_IP_BINDING, global.GCONFIG_ENABLE_DEVICE_FINGERPRINT, global.GCONFIG_RECORD_FORCE_BIND_2FA
	oldDays, oldHistory := global.GCONFIG_PWD_EXPIRE_DAYS, global.GCONFIG_PWD_HISTORY_COUNT
	global.GWAF_TENANT_ID, global.GWAF_USER_CODE = "session-tenant", "session-user"
	global.GCONFIG_COMM_LEGACY_KEY, global.GWAF_RELEASE = true, "true"
	global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES = 30
	global.GCONFIG_ENABLE_STRICT_IP_BINDING, global.GCONFIG_ENABLE_DEVICE_FINGERPRINT, global.GCONFIG_RECORD_FORCE_BIND_2FA = 0, 0, 0
	global.GCONFIG_PWD_EXPIRE_DAYS, global.GCONFIG_PWD_HISTORY_COUNT = 0, 0
	global.GCACHE_WAFCACHE = &sessionRetainedCache{cache.InitWafCache()}
	db, err := gorm.Open(sqlitedriver.Open(filepath.Join(t.TempDir(), "session.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	global.GWAF_LOCAL_DB = db
	if err = db.AutoMigrate(&model.Account{}, &model.TokenInfo{}, &model.AccountPwdHistory{}); err != nil {
		t.Fatal(err)
	}
	if err = db.Callback().Query().Before("gorm:query").Register("tenant_plugin:before_query", func(d *gorm.DB) {
		d.Where("tenant_id = ? and user_code=? ", global.GWAF_TENANT_ID, global.GWAF_USER_CODE)
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
		global.GWAF_LOCAL_DB, global.GCACHE_WAFCACHE = oldDB, oldCache
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = oldTenant, oldUser
		global.GCONFIG_COMM_LEGACY_KEY, global.GWAF_RELEASE = oldLegacy, oldRelease
		global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES, global.GCONFIG_ENABLE_STRICT_IP_BINDING, global.GCONFIG_ENABLE_DEVICE_FINGERPRINT, global.GCONFIG_RECORD_FORCE_BIND_2FA = oldTTL, oldIP, oldFP, oldOTP
		global.GCONFIG_PWD_EXPIRE_DAYS, global.GCONFIG_PWD_HISTORY_COUNT = oldDays, oldHistory
	})
	return db
}

func sessionAccount(t *testing.T, db *gorm.DB, name, role string, status int) model.Account {
	t.Helper()
	hash, err := utils.BcryptHash("SessionTest#Password27")
	if err != nil {
		t.Fatal(err)
	}
	now := customtype.JsonTime(time.Now())
	account := model.Account{BaseOrm: baseorm.BaseOrm{Id: fmt.Sprintf("%s-%s-%s", name, global.GWAF_TENANT_ID, global.GWAF_USER_CODE), Tenant_ID: global.GWAF_TENANT_ID, USER_CODE: global.GWAF_USER_CODE, CREATE_TIME: now, UPDATE_TIME: now}, LoginAccount: name, LoginPassword: hash, Role: role, Status: status, PwdUpdateTime: time.Now().Format("2006-01-02 15:04:05")}
	if err = db.Create(&account).Error; err != nil {
		t.Fatal(err)
	}
	return account
}

func sessionIssue(t *testing.T, account model.Account, kind, token string) model.TokenInfo {
	t.Helper()
	bean, err := waf_service.WafTokenInfoServiceApp.IssueSession(account, token, "127.0.0.1", "", kind, "SessionTest#Password27")
	if err != nil {
		t.Fatal(err)
	}
	global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_TOKEN+token, *bean, time.Hour)
	return *bean
}

func sessionRequest(t *testing.T, token, kind, path string, roles ...string) (int, bool) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	reached := false
	router.GET(path, Auth(), RequireRole(roles...), func(c *gin.Context) { reached = true; c.JSON(200, gin.H{"code": 0}) })
	req := httptest.NewRequest("GET", path, nil)
	if kind == "mobile" {
		req.Header.Set("X-Login-Type", kind)
		req.Header.Set("X-Mobile-Token", token)
	} else {
		req.Header.Set("X-Token", token)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	var body struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Code, reached
}

func sessionExpect(t *testing.T, token, kind string, expected int, roles ...string) {
	t.Helper()
	code, reached := sessionRequest(t, token, kind, "/api/v1/session-check", roles...)
	if code != expected || reached != (expected == response.SUCCESS) {
		t.Fatalf("%s: code=%d reached=%v expected=%d", kind, code, reached, expected)
	}
}

func dialSessionWebSocket(t *testing.T) (*gws.Conn, *gws.Conn) {
	t.Helper()
	upGrader := gws.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	upgraded := make(chan *gws.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade 失败: %v", err)
			return
		}
		upgraded <- conn
		select {}
	}))
	t.Cleanup(server.Close)
	client, _, err := gws.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client, <-upgraded
}

func registerSessionWebSocket(t *testing.T, online *gwebsocket.WebSocketOnline, token model.TokenInfo, server *gws.Conn) string {
	t.Helper()
	sessionID, err := online.AddValidatedAccountWebSocket(token.Tenant_ID, token.USER_CODE, token.LoginAccount, "", server, func() error {
		_, err := waf_service.WafTokenInfoServiceApp.ValidateSession(token, token.AccessToken)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return sessionID
}

func TestAccountSessionClosesWebSocketConnections(t *testing.T) {
	db := sessionFixture(t)
	account := sessionAccount(t, db, "operator", enums.ROLE_SUPER_ADMIN, 0)
	sessionAccount(t, db, "other", enums.ROLE_SUPER_ADMIN, 0)
	oldOnline := global.GWebSocket
	online := gwebsocket.InitWafWebSocket()
	global.GWebSocket = online
	t.Cleanup(func() { global.GWebSocket = oldOnline })

	operatorToken := sessionIssue(t, account, "web", "operator-ws")
	otherAccount, err := waf_service.WafAccountServiceApp.GetLoginAccount("other")
	if err != nil {
		t.Fatal(err)
	}
	otherToken := sessionIssue(t, otherAccount, "web", "other-ws")
	operatorClient, operatorServer := dialSessionWebSocket(t)
	otherClient, otherServer := dialSessionWebSocket(t)
	defer operatorServer.Close()
	defer otherServer.Close()
	_ = registerSessionWebSocket(t, online, operatorToken, operatorServer)
	_ = registerSessionWebSocket(t, online, otherToken, otherServer)

	if err = waf_service.WafAccountServiceApp.ModifyApi(request.WafAccountEditReq{Id: account.Id, LoginAccount: account.LoginAccount, Status: account.Status, Role: enums.ROLE_AUDIT_ADMIN}, enums.ROLE_SUPER_ADMIN); err != nil {
		t.Fatal(err)
	}
	operatorClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err = operatorClient.ReadMessage(); err == nil {
		t.Fatal("目标账号变更后，其 WebSocket 连接应被关闭")
	}
	otherClient.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err = otherClient.WriteMessage(gws.TextMessage, []byte("ping")); err != nil {
		t.Fatalf("无关账号连接不应被关闭: %v", err)
	}
	if got := online.OnlineCount(); got != 1 {
		t.Fatalf("仅应保留无关账号连接，实际在线 %d", got)
	}
}

func TestAccountSessionChanges(t *testing.T) {
	for _, change := range []string{"role", "login", "status", "delete", "remarks"} {
		t.Run(change, func(t *testing.T) {
			db := sessionFixture(t)
			account := sessionAccount(t, db, "operator", enums.ROLE_SUPER_ADMIN, 0)
			other := sessionAccount(t, db, "other", enums.ROLE_SUPER_ADMIN, 1)
			sessionIssue(t, account, "web", "operator-web")
			sessionIssue(t, account, "mobile", "operator-mobile")
			sessionIssue(t, other, "web", "other-web")
			sessionExpect(t, "operator-web", "web", 0)
			sessionExpect(t, "operator-mobile", "mobile", 0)
			req := request.WafAccountEditReq{Id: account.Id, LoginAccount: account.LoginAccount, Status: account.Status, Remarks: "updated"}
			switch change {
			case "role":
				req.Role = enums.ROLE_AUDIT_ADMIN
			case "login":
				req.LoginAccount = "renamed"
			case "status":
				req.Status = 1
			}
			var err error
			if change == "delete" {
				err = waf_service.WafAccountServiceApp.DelApi(request.WafAccountDelReq{Id: account.Id})
			} else {
				err = waf_service.WafAccountServiceApp.ModifyApi(req, enums.ROLE_SUPER_ADMIN)
			}
			if err != nil {
				t.Fatal(err)
			}
			want := response.AUTHFAIL
			if change == "remarks" {
				want = 0
			}
			sessionExpect(t, "operator-web", "web", want)
			sessionExpect(t, "operator-mobile", "mobile", want)
			sessionExpect(t, "other-web", "web", 0)
			if change == "delete" {
				rebuilt := account
				rebuilt.Id = "rebuilt-account"
				if err = db.Create(&rebuilt).Error; err != nil {
					t.Fatal(err)
				}
				sessionExpect(t, "operator-web", "web", response.AUTHFAIL)
				if _, err = waf_service.WafTokenInfoServiceApp.IssueSession(account, "stale-login", "", "", "web", "SessionTest#Password27"); !errors.Is(err, waf_service.ErrSessionInvalid) {
					t.Fatalf("stale account: %v", err)
				}
			}
			if change == "role" {
				current, err := waf_service.WafAccountServiceApp.GetLoginAccount(account.LoginAccount)
				if err != nil {
					t.Fatal(err)
				}
				sessionIssue(t, current, "web", "new-audit-web")
				sessionExpect(t, "new-audit-web", "web", response.FORBIDDEN, enums.ROLE_SYSTEM_ADMIN)
				sessionExpect(t, "new-audit-web", "web", 0, enums.ROLE_AUDIT_ADMIN)
			}
			if change == "status" {
				current, _ := waf_service.WafAccountServiceApp.GetLoginAccount(account.LoginAccount)
				sessionIssue(t, current, "mobile", "status-one-mobile")
				sessionExpect(t, "status-one-mobile", "mobile", 0)
			}
			global.GCACHE_WAFCACHE = cache.InitWafCache()
			if err = waf_service.WafTokenInfoServiceApp.ReloadAllValidTokensToCache(); err != nil {
				t.Fatal(err)
			}
			sessionExpect(t, "operator-web", "web", want)
			sessionExpect(t, "other-web", "web", 0)
		})
	}
}

func TestAccountSessionIdentityAndCurrentRole(t *testing.T) {
	db := sessionFixture(t)
	account := sessionAccount(t, db, "operator", enums.ROLE_SUPER_ADMIN, 0)
	token := sessionIssue(t, account, "web", "identity-web")
	for _, mutation := range []string{"id", "token", "tenant", "user"} {
		bad := token
		switch mutation {
		case "id":
			bad.Id = "other-id"
		case "token":
			bad.AccessToken = "other-token"
		case "tenant":
			bad.Tenant_ID = "other-tenant"
		case "user":
			bad.USER_CODE = "other-user"
		}
		global.GCACHE_WAFCACHE.SetWithTTlRenewTime(enums.CACHE_TOKEN+token.AccessToken, bad, time.Hour)
		sessionExpect(t, token.AccessToken, "web", response.AUTHFAIL)
	}
	global.GCACHE_WAFCACHE.SetWithTTlRenewTime(enums.CACHE_TOKEN+token.AccessToken, token, time.Hour)
	if err := db.Model(&model.Account{}).Where("id = ? AND tenant_id = ? AND user_code = ?", account.Id, account.Tenant_ID, account.USER_CODE).Update("role", enums.ROLE_AUDIT_ADMIN).Error; err != nil {
		t.Fatal(err)
	}
	sessionExpect(t, token.AccessToken, "web", response.AUTHFAIL, enums.ROLE_SYSTEM_ADMIN)
}

func TestAccountSessionStorageFailures(t *testing.T) {
	db := sessionFixture(t)
	account := sessionAccount(t, db, "operator", enums.ROLE_SUPER_ADMIN, 0)
	sessionAccount(t, db, "other", enums.ROLE_SUPER_ADMIN, 0)
	sessionIssue(t, account, "web", "failure-web")
	sessionIssue(t, account, "mobile", "failure-mobile")
	if err := db.Callback().Query().Before("gorm:query").Register("session_test:query_error", func(tx *gorm.DB) { tx.AddError(errors.New("storage read unavailable")) }); err != nil {
		t.Fatal(err)
	}
	sessionExpect(t, "failure-web", "web", response.BACKEND_UNAVAILABLE)
	sessionExpect(t, "failure-mobile", "mobile", response.BACKEND_UNAVAILABLE)
	_ = db.Callback().Query().Remove("session_test:query_error")
	sessionExpect(t, "failure-web", "web", 0)
	if err := db.Callback().Delete().Before("gorm:delete").Register("session_test:delete_error", func(tx *gorm.DB) {
		if tx.Statement.Table == "token_infos" {
			tx.AddError(errors.New("session delete unavailable"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	err := waf_service.WafAccountServiceApp.ModifyApi(request.WafAccountEditReq{Id: account.Id, LoginAccount: account.LoginAccount, Role: enums.ROLE_AUDIT_ADMIN}, enums.ROLE_SUPER_ADMIN)
	if !errors.Is(err, waf_service.ErrSessionBackend) {
		t.Fatalf("modify: %v", err)
	}
	err = waf_service.WafAccountServiceApp.DelApi(request.WafAccountDelReq{Id: account.Id})
	if !errors.Is(err, waf_service.ErrSessionBackend) {
		t.Fatalf("delete: %v", err)
	}
	if _, err = waf_service.WafTokenInfoServiceApp.IssueSession(account, "replacement", "", "", "web", "SessionTest#Password27"); !errors.Is(err, waf_service.ErrSessionBackend) {
		t.Fatalf("issue: %v", err)
	}
	_ = db.Callback().Delete().Remove("session_test:delete_error")
	sessionExpect(t, "failure-web", "web", 0)
	sessionExpect(t, "failure-mobile", "mobile", 0)
	current, _ := waf_service.WafAccountServiceApp.GetLoginAccount(account.LoginAccount)
	if current.Role != account.Role {
		t.Fatal("account update did not roll back")
	}
}

func TestAccountSessionTenantIsolation(t *testing.T) {
	db := sessionFixture(t)
	account := sessionAccount(t, db, "operator", enums.ROLE_SUPER_ADMIN, 0)
	sessionAccount(t, db, "other", enums.ROLE_SUPER_ADMIN, 0)
	sessionIssue(t, account, "web", "scope-current")
	tenant, user := global.GWAF_TENANT_ID, global.GWAF_USER_CODE
	for _, axis := range []string{"tenant", "user"} {
		if axis == "tenant" {
			global.GWAF_TENANT_ID = "foreign-tenant"
		} else {
			global.GWAF_USER_CODE = "foreign-user"
		}
		foreign := sessionAccount(t, db, "operator", enums.ROLE_SUPER_ADMIN, 0)
		sessionIssue(t, foreign, "web", "scope-"+axis)
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = tenant, user
		if err := waf_service.WafAccountServiceApp.ModifyApi(request.WafAccountEditReq{Id: foreign.Id, LoginAccount: "operator", Status: 1}, enums.ROLE_SUPER_ADMIN); !errors.Is(err, waf_service.ErrSessionInvalid) {
			t.Fatalf("foreign modify: %v", err)
		}
		if err := waf_service.WafAccountServiceApp.DelApi(request.WafAccountDelReq{Id: foreign.Id}); !errors.Is(err, waf_service.ErrSessionInvalid) {
			t.Fatalf("foreign delete: %v", err)
		}
		sessionExpect(t, "scope-"+axis, "web", response.AUTHFAIL)
	}
	if err := waf_service.WafAccountServiceApp.DelApi(request.WafAccountDelReq{Id: account.Id}); err != nil {
		t.Fatal(err)
	}
	for _, axis := range []string{"tenant", "user"} {
		global.GWAF_TENANT_ID, global.GWAF_USER_CODE = tenant, user
		if axis == "tenant" {
			global.GWAF_TENANT_ID = "foreign-tenant"
		} else {
			global.GWAF_USER_CODE = "foreign-user"
		}
		sessionExpect(t, "scope-"+axis, "web", 0)
	}
}

func TestAccountSessionLoginBoundary(t *testing.T) {
	for _, change := range []string{"role", "status", "login", "delete"} {
		t.Run(change, func(t *testing.T) {
			db := sessionFixture(t)
			account := sessionAccount(t, db, "operator", enums.ROLE_SUPER_ADMIN, 0)
			sessionAccount(t, db, "other", enums.ROLE_SUPER_ADMIN, 0)
			start := make(chan struct{})
			var wg sync.WaitGroup
			var issueErr, changeErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				_, issueErr = waf_service.WafTokenInfoServiceApp.IssueSession(account, "racing-login", "", "", "web", "SessionTest#Password27")
			}()
			go func() {
				defer wg.Done()
				<-start
				req := request.WafAccountEditReq{Id: account.Id, LoginAccount: account.LoginAccount, Status: account.Status}
				switch change {
				case "role":
					req.Role = enums.ROLE_AUDIT_ADMIN
				case "status":
					req.Status = 1
				case "login":
					req.LoginAccount = "renamed"
				}
				if change == "delete" {
					changeErr = waf_service.WafAccountServiceApp.DelApi(request.WafAccountDelReq{Id: account.Id})
				} else {
					changeErr = waf_service.WafAccountServiceApp.ModifyApi(req, enums.ROLE_SUPER_ADMIN)
				}
			}()
			close(start)
			wg.Wait()
			if changeErr != nil {
				t.Fatal(changeErr)
			}
			if issueErr != nil && !errors.Is(issueErr, waf_service.ErrSessionInvalid) {
				t.Fatal(issueErr)
			}
			var count int64
			if err := db.Model(&model.TokenInfo{}).Where("tenant_id = ? AND user_code = ? AND access_token = ?", global.GWAF_TENANT_ID, global.GWAF_USER_CODE, "racing-login").Count(&count).Error; err != nil || count != 0 {
				t.Fatalf("count=%d error=%v", count, err)
			}
			if _, err := waf_service.WafTokenInfoServiceApp.IssueSession(account, "late-login", "", "", "mobile", "SessionTest#Password27"); !errors.Is(err, waf_service.ErrSessionInvalid) {
				t.Fatalf("late login: %v", err)
			}
		})
	}
}

func TestAccountSessionReplacementAndPasswordGate(t *testing.T) {
	db := sessionFixture(t)
	account := sessionAccount(t, db, "operator", "", 0)
	sessionIssue(t, account, "web", "first-web")
	sessionIssue(t, account, "mobile", "first-mobile")
	sessionIssue(t, account, "web", "second-web")
	sessionExpect(t, "first-web", "web", response.AUTHFAIL)
	sessionExpect(t, "first-mobile", "mobile", 0)
	sessionExpect(t, "second-web", "web", 0)
	if err := db.Model(&model.Account{}).Where("id = ? AND tenant_id = ? AND user_code = ?", account.Id, account.Tenant_ID, account.USER_CODE).Update("need_change_password", 1).Error; err != nil {
		t.Fatal(err)
	}
	global.GCACHE_WAFCACHE = cache.InitWafCache()
	if err := waf_service.WafTokenInfoServiceApp.ReloadAllValidTokensToCache(); err != nil {
		t.Fatal(err)
	}
	sessionExpect(t, "second-web", "web", response.NEED_CHANGE_PWD)
	code, reached := sessionRequest(t, "first-mobile", "mobile", "/api/v1/account/changemypwd")
	if code != 0 || !reached {
		t.Fatalf("change password route: %d %v", code, reached)
	}
	if err := waf_service.WafAccountServiceApp.ChangeMyPasswordApi("operator", "SessionTest#Password27", "NewSessionTest#Password28"); err != nil {
		t.Fatal(err)
	}
	sessionExpect(t, "second-web", "web", 0)
	sessionExpect(t, "first-mobile", "mobile", 0)

	// 管理员重置密码：目标账号既有会话不再保留，登录后先走改密流程。
	sessionAccount(t, db, "super", enums.ROLE_SUPER_ADMIN, 0)
	account, err := waf_service.WafAccountServiceApp.GetLoginAccount("operator")
	if err != nil {
		t.Fatal(err)
	}
	sessionIssue(t, account, "web", "reset-web")
	sessionIssue(t, account, "mobile", "reset-mobile")
	if err := waf_service.WafAccountServiceApp.ResetPwdApi(request.WafAccountResetPwdReq{Id: account.Id, LoginAccount: "operator", LoginSuperPassword: "SessionTest#Password27", LoginNewPassword: "ResetSessionTest#Password29", LoginNewPassword2: "ResetSessionTest#Password29"}); err != nil {
		t.Fatal(err)
	}
	sessionExpect(t, "reset-web", "web", response.AUTHFAIL)
	sessionExpect(t, "reset-mobile", "mobile", response.AUTHFAIL)
	current, err := waf_service.WafAccountServiceApp.GetLoginAccount("operator")
	if err != nil {
		t.Fatal(err)
	}
	token := sessionIssue(t, current, "web", "after-reset-web")
	sessionExpect(t, token.AccessToken, "web", response.NEED_CHANGE_PWD)
}

func TestAccountSessionManagementAPIFailureCodes(t *testing.T) {
	db := sessionFixture(t)
	account := sessionAccount(t, db, "operator", enums.ROLE_SUPER_ADMIN, 0)
	sessionAccount(t, db, "other", enums.ROLE_SUPER_ADMIN, 0)
	sessionIssue(t, account, "web", "api-web")
	if err := db.Callback().Delete().Before("gorm:delete").Register("session_test:delete_error", func(tx *gorm.DB) { tx.AddError(errors.New("storage unavailable")) }); err != nil {
		t.Fatal(err)
	}
	defer db.Callback().Delete().Remove("session_test:delete_error")
	for _, operation := range []string{"modify", "delete", "reset"} {
		router := gin.New()
		handler := (&api.WafAccountApi{}).ModifyAccountApi
		payload := fmt.Sprintf(`{"id":%q,"login_account":"operator","role":"auditAdmin"}`, account.Id)
		if operation == "delete" {
			handler = (&api.WafAccountApi{}).DelAccountApi
			payload = fmt.Sprintf(`{"id":%q}`, account.Id)
		}
		if operation == "reset" {
			handler = (&api.WafAccountApi{}).ResetAccountPwdApi
			payload = fmt.Sprintf(`{"id":%q,"login_account":"operator","login_super_password":"SessionTest#Password27","login_new_password":"ResetSessionTest#Password29","login_new_password2":"ResetSessionTest#Password29"}`, account.Id)
		}
		router.POST("/api/v1/session-operation", Auth(), handler)
		req := httptest.NewRequest("POST", "/api/v1/session-operation", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Token", "api-web")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		var body struct {
			Code int `json:"code"`
		}
		_ = json.Unmarshal(recorder.Body.Bytes(), &body)
		if body.Code != response.BACKEND_UNAVAILABLE {
			t.Fatalf("%s: %s", operation, recorder.Body.String())
		}
		sessionExpect(t, "api-web", "web", 0)
	}
}

func TestAccountSessionManagementAPINotFoundCodes(t *testing.T) {
	db := sessionFixture(t)
	account := sessionAccount(t, db, "operator", enums.ROLE_SUPER_ADMIN, 0)
	sessionIssue(t, account, "web", "not-found-web")
	for _, operation := range []string{"modify", "delete", "reset"} {
		router := gin.New()
		handler := (&api.WafAccountApi{}).ModifyAccountApi
		payload := `{"id":"missing-account","login_account":"operator","role":"auditAdmin"}`
		if operation == "delete" {
			handler = (&api.WafAccountApi{}).DelAccountApi
			payload = `{"id":"missing-account"}`
		}
		if operation == "reset" {
			handler = (&api.WafAccountApi{}).ResetAccountPwdApi
			payload = `{"id":"missing-account","login_account":"missing-account","login_super_password":"SessionTest#Password27","login_new_password":"ResetSessionTest#Password29","login_new_password2":"ResetSessionTest#Password29"}`
		}
		router.POST("/api/v1/session-operation", Auth(), handler)
		req := httptest.NewRequest("POST", "/api/v1/session-operation", bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Token", "not-found-web")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		var body struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
		}
		_ = json.Unmarshal(recorder.Body.Bytes(), &body)
		if body.Code != response.ERROR || body.Msg != "账号不存在" {
			t.Fatalf("%s: %s", operation, recorder.Body.String())
		}
	}
}
