package api

import (
	"SamWaf/global"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// 测试用例 ExportExcelApi
func TestExportExcelApi(t *testing.T) {
	// 创建一个基于 Gin 的引擎
	r := gin.Default()

	global.GWAF_RELEASE_VERSION = "111"
	r.GET("/samwaf/export", new(WafCommonApi).ExportExcelApi)
	// 创建一个模拟的 HTTP 请求 WafCommonReq 对象
	// 创建一个模拟的 HTTP 请求
	queryParams := url.Values{}
	queryParams.Set("table_name", "hosts")

	req, err := http.NewRequest(http.MethodGet, "/samwaf/export?"+queryParams.Encode(), nil)
	if err != nil {
		t.Fatalf("无法创建请求：%v", err)
	}

	// 创建一个响应记录器
	rec := httptest.NewRecorder()

	// 将模拟的请求发送到测试的 API 路由
	r.ServeHTTP(rec, req)

	// 检查响应状态码是否为 200
	if rec.Code != http.StatusOK {
		t.Errorf("期望的状态码：%d，实际状态码：%d", http.StatusOK, rec.Code)
	}
}
