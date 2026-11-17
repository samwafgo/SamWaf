package router

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/middleware"
	"SamWaf/wafdb/dialect"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	sqlitedriver "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// stubLocalCoreDB 给会走到 service 层的用例挂一个未迁移的本地库：
// 查询必然失败，handler 走常规错误分支返回，不依赖真实数据。
func stubLocalCoreDB(t *testing.T) {
	t.Helper()
	dialect.Register(&dialect.SQLiteDialect{})
	dsn := filepath.Join(t.TempDir(), "core.db") + "?_db_key=" + "ktest"
	db, err := gorm.Open(sqlitedriver.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("打开本地测试库失败: %v", err)
	}
	old := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = db
	t.Cleanup(func() {
		global.GWAF_LOCAL_DB = old
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	})
}

func caserverInfoRequest(t *testing.T, role string, auth bool, method, path string) (int, string) {
	t.Helper()
	r := gin.New()
	group := r.Group("")
	if auth {
		group.Use(middleware.Auth())
	} else {
		group.Use(func(c *gin.Context) { c.Set("userRole", role) })
	}
	new(WafCaServerInfoRouter).InitWafCaServerInfoRouter(group)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	var reply struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("response=%s err=%v", rec.Body.String(), err)
	}
	return reply.Code, reply.Msg
}

// TestCaServerInfoRouteAuthenticationAndRoles 护栏：写接口限系统管理员，读接口对所有登录角色开放。
// 反向验证过：摘掉 writeRouter 的 RequireRole 后，security/audit 用例由 -403 变 -1、用例变红。
func TestCaServerInfoRouteAuthenticationAndRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stubLocalCoreDB(t)

	t.Run("unauthenticated", func(t *testing.T) {
		code, _ := caserverInfoRequest(t, "", true, "POST", "/api/v1/wafhost/caserverinfo/add")
		if code != -999 {
			t.Fatalf("未认证访问写接口 code=%d，期望-999", code)
		}
	})

	// 写接口（add/del 代表全部写接口的门禁行为）
	for _, tc := range []struct {
		role string
		want int
	}{
		{enums.ROLE_SUPER_ADMIN, -1},
		{enums.ROLE_SYSTEM_ADMIN, -1},
		{enums.ROLE_SECURITY_ADMIN, -403},
		{enums.ROLE_AUDIT_ADMIN, -403},
	} {
		t.Run("add/"+tc.role, func(t *testing.T) {
			code, msg := caserverInfoRequest(t, tc.role, false, "POST", "/api/v1/wafhost/caserverinfo/add")
			if code != tc.want {
				t.Fatalf("response code=%d msg=%s，期望%d", code, msg, tc.want)
			}
		})
		t.Run("del/"+tc.role, func(t *testing.T) {
			code, msg := caserverInfoRequest(t, tc.role, false, "GET", "/api/v1/wafhost/caserverinfo/del")
			if code != tc.want {
				t.Fatalf("response code=%d msg=%s，期望%d", code, msg, tc.want)
			}
		})
	}

	// 读接口对所有登录角色开放
	for _, role := range []string{enums.ROLE_SUPER_ADMIN, enums.ROLE_SYSTEM_ADMIN, enums.ROLE_SECURITY_ADMIN, enums.ROLE_AUDIT_ADMIN} {
		t.Run("list/"+role, func(t *testing.T) {
			code, _ := caserverInfoRequest(t, role, false, "POST", "/api/v1/wafhost/caserverinfo/list")
			if code != -1 { // 空请求体在绑定阶段即失败，能走到这里说明已通过角色门
				t.Fatalf("list code=%d，期望-1", code)
			}
		})
		t.Run("detail/"+role, func(t *testing.T) {
			code, _ := caserverInfoRequest(t, role, false, "GET", "/api/v1/wafhost/caserverinfo/detail")
			if code != 0 { // 空库查不到记录，正常返回空详情
				t.Fatalf("detail code=%d，期望0", code)
			}
		})
	}
}
