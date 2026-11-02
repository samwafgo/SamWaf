package router

import (
	"SamWaf/global"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

const appDirPreviewPath = "/api/v1/application/app/directory_preview"

// setupAppDirPreviewEngine 挂真实路由，借 is_openapi 标记拿到明文 JSON 响应
func setupAppDirPreviewEngine(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	root := t.TempDir()
	priorEnabled, priorDirs := global.GWAF_CAN_APP_MANAGE, global.GWAF_APP_ALLOW_DIRS
	global.GWAF_CAN_APP_MANAGE = true
	global.GWAF_APP_ALLOW_DIRS = root
	t.Cleanup(func() {
		global.GWAF_CAN_APP_MANAGE, global.GWAF_APP_ALLOW_DIRS = priorEnabled, priorDirs
	})

	r := gin.New()
	group := r.Group("", func(c *gin.Context) { c.Set("is_openapi", true) })
	new(WafAppRouter).InitWafAppRouter(group)
	return r, root
}


func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("请求体构造失败: %v", err)
	}
	return raw
}

func postDirPreview(t *testing.T, r *gin.Engine, payload map[string]string) (int, map[string]interface{}) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("请求体构造失败: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, appDirPreviewPath, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var reply struct {
		Code int                    `json:"code"`
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("响应解析失败 body=%s err=%v", rec.Body.String(), err)
	}
	return reply.Code, reply.Data
}

func TestDirectoryPreviewValidDefault(t *testing.T) {
	r, root := setupAppDirPreviewEngine(t)
	code, data := postDirPreview(t, r, map[string]string{"code": "app-prev-1", "app_dir": ""})
	if code != 0 {
		t.Fatalf("code=%d data=%v", code, data)
	}
	want := filepath.Join(root, "app-prev-1")
	if data["valid"] != true || data["resolved_dir"] != want || data["default_dir"] != want {
		t.Fatalf("data=%v want resolved=%q", data, want)
	}
	if data["path_base"] != root {
		t.Fatalf("path_base=%v want %q", data["path_base"], root)
	}
	allowed, ok := data["allowed_dirs"].([]interface{})
	if !ok || len(allowed) != 1 || allowed[0] != root {
		t.Fatalf("allowed_dirs=%v", data["allowed_dirs"])
	}
	// 预检不落盘：默认目录不得被创建
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Fatalf("预览不得创建目录, stat err=%v", err)
	}
}

func TestDirectoryPreviewValidExplicit(t *testing.T) {
	r, root := setupAppDirPreviewEngine(t)
	explicit := filepath.Join(root, "custom")
	code, data := postDirPreview(t, r, map[string]string{"code": "app-prev-2", "app_dir": explicit})
	if code != 0 || data["valid"] != true || data["resolved_dir"] != explicit {
		t.Fatalf("code=%d data=%v", code, data)
	}
}

func TestDirectoryPreviewOutOfRange(t *testing.T) {
	r, _ := setupAppDirPreviewEngine(t)
	outside := t.TempDir()
	code, data := postDirPreview(t, r, map[string]string{"code": "app-prev-3", "app_dir": outside})
	// 非法范围：业务码 0，valid=false 并回显实际解析路径
	if code != 0 {
		t.Fatalf("code=%d data=%v", code, data)
	}
	if data["valid"] != false || data["error"] == "" {
		t.Fatalf("data=%v", data)
	}
	if data["resolved_dir"] != outside {
		t.Fatalf("resolved_dir=%v want %q", data["resolved_dir"], outside)
	}
}

func TestDirectoryPreviewInvalidParams(t *testing.T) {
	r, _ := setupAppDirPreviewEngine(t)
	// 目录穿越 code：业务错误码
	code, _ := postDirPreview(t, r, map[string]string{"code": "../evil", "app_dir": ""})
	if code == 0 {
		t.Fatal("非法 code 必须返回业务错误码")
	}
	// 缺失必填 code：binding 失败
	code, _ = postDirPreview(t, r, map[string]string{"app_dir": ""})
	if code == 0 {
		t.Fatal("缺失 code 必须返回业务错误码")
	}
	// code 超长
	code, _ = postDirPreview(t, r, map[string]string{"code": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "app_dir": ""})
	if code == 0 {
		t.Fatal("超长 code 必须返回业务错误码")
	}
}

func TestDirectoryPreviewNoOpPasswordRequired(t *testing.T) {
	r, _ := setupAppDirPreviewEngine(t)
	// 不带 X-App-Op-Password 头：在 AppManageEnabled 组（非 dangerGroup）应直达处理器
	req := httptest.NewRequest(http.MethodPost, appDirPreviewPath, bytes.NewReader(mustJSON(t, map[string]string{"code": "app-prev-4", "app_dir": ""})))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var reply struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil || reply.Code != 0 {
		t.Fatalf("response=%s err=%v", rec.Body.String(), err)
	}
}

func TestDirectoryPreviewDisabledFeature(t *testing.T) {
	r, _ := setupAppDirPreviewEngine(t)
	global.GWAF_CAN_APP_MANAGE = false
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, appDirPreviewPath, bytes.NewReader(mustJSON(t, map[string]string{"code": "app-prev-5", "app_dir": ""})))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
