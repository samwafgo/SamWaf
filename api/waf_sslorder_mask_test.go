package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/wafsec"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	sqlite "github.com/samwafgo/sqlitedriver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupSslOrderMaskTest 造一个带私钥字段的证书订单，供角色可见性用例查询。
func setupSslOrderMaskTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "core.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.SslOrder{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB, _ := db.DB(); sqlDB.Close() })
	old := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = db
	t.Cleanup(func() { global.GWAF_LOCAL_DB = old })

	order := model.SslOrder{
		BaseOrm:           baseorm.BaseOrm{Id: "order-mask-1", USER_CODE: global.GWAF_USER_CODE, Tenant_ID: global.GWAF_TENANT_ID},
		HostCode:          "host-1",
		ApplyPlatform:     "letsencrypt",
		ApplyMethod:       "http01",
		ApplyDomain:       "xxxx.com",
		ApplyStatus:       "success",
		ApplyKey:          "APPLY_KEY_MATERIAL",
		ResultPrivateKey:  []byte("PRIVATE_KEY_MATERIAL"),
		ResultCertificate: []byte("CERT_MATERIAL"),
	}
	if err := db.Create(&order).Error; err != nil {
		t.Fatal(err)
	}
}

// sslOrderQuery 按角色调用 detail/list。管理端响应按统一出口加密，
// 这里解密后返回 data 载荷原文；OpenAPI 响应本来就是明文。
func sslOrderQuery(t *testing.T, role string, openapi bool, method, path string, body []byte) []byte {
	t.Helper()
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if openapi {
			c.Set("is_openapi", true)
		} else {
			c.Set("userRole", role)
		}
	})
	api := &WafSslOrderApi{}
	r.GET("/detail", api.GetDetailApi)
	r.POST("/list", api.GetListApi)
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var reply struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("response=%s err=%v", rec.Body.Bytes(), err)
	}
	if reply.Code != 0 {
		t.Fatalf("response=%s", rec.Body.Bytes())
	}
	var dataStr string
	if err := json.Unmarshal(reply.Data, &dataStr); err == nil {
		if plain, err := wafsec.AesDecrypt(dataStr, global.GWAF_COMMUNICATION_KEY); err == nil {
			return plain
		}
	}
	return reply.Data
}

// TestSslOrderSecretsRoleVisibility 护栏：证书订单的私钥字段仅系统管理员与超管可见，
// 其余角色与 OpenAPI Key 调用一律被置空。
// 反向验证过：把 maskSslOrderSecrets 改成 no-op 后，审计/安全角色用例重新搜到私钥、用例变红。
func TestSslOrderSecretsRoleVisibility(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupSslOrderMaskTest(t)

	privateKeyB64 := base64.StdEncoding.EncodeToString([]byte("PRIVATE_KEY_MATERIAL"))

	t.Run("detail/auditAdmin不可见", func(t *testing.T) {
		resp := sslOrderQuery(t, enums.ROLE_AUDIT_ADMIN, false, "GET", "/detail?id=order-mask-1", nil)
		if bytes.Contains(resp, []byte(privateKeyB64)) || bytes.Contains(resp, []byte("APPLY_KEY_MATERIAL")) {
			t.Fatalf("审计角色拿到私钥: %s", resp)
		}
	})
	t.Run("detail/securityAdmin不可见", func(t *testing.T) {
		resp := sslOrderQuery(t, enums.ROLE_SECURITY_ADMIN, false, "GET", "/detail?id=order-mask-1", nil)
		if bytes.Contains(resp, []byte(privateKeyB64)) {
			t.Fatalf("安全角色拿到私钥: %s", resp)
		}
	})
	t.Run("detail/openapi不可见", func(t *testing.T) {
		resp := sslOrderQuery(t, "", true, "GET", "/detail?id=order-mask-1", nil)
		if bytes.Contains(resp, []byte(privateKeyB64)) {
			t.Fatalf("OpenAPI调用拿到私钥: %s", resp)
		}
	})
	t.Run("detail/systemAdmin可见", func(t *testing.T) {
		resp := sslOrderQuery(t, enums.ROLE_SYSTEM_ADMIN, false, "GET", "/detail?id=order-mask-1", nil)
		if !bytes.Contains(resp, []byte(privateKeyB64)) {
			t.Fatalf("系统管理员应看到私钥: %s", resp)
		}
	})
	t.Run("detail/superAdmin可见", func(t *testing.T) {
		resp := sslOrderQuery(t, enums.ROLE_SUPER_ADMIN, false, "GET", "/detail?id=order-mask-1", nil)
		if !bytes.Contains(resp, []byte(privateKeyB64)) {
			t.Fatalf("超管应看到私钥: %s", resp)
		}
	})
	t.Run("list/auditAdmin不可见", func(t *testing.T) {
		resp := sslOrderQuery(t, enums.ROLE_AUDIT_ADMIN, false, "POST", "/list", []byte(`{"pageIndex":1,"pageSize":10}`))
		if bytes.Contains(resp, []byte(privateKeyB64)) {
			t.Fatalf("审计角色列表拿到私钥: %s", resp)
		}
	})
	t.Run("list/systemAdmin可见", func(t *testing.T) {
		resp := sslOrderQuery(t, enums.ROLE_SYSTEM_ADMIN, false, "POST", "/list", []byte(`{"pageIndex":1,"pageSize":10}`))
		if !bytes.Contains(resp, []byte(privateKeyB64)) {
			t.Fatalf("系统管理员列表应看到私钥: %s", resp)
		}
	})
}
