package api

import (
	"SamWaf/global"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 响应体：{"message":"H       ello, World!"}，实际响应体：{"code":0,"data":{"need_update":false,"versi       on":"555","version_name":"1.0","version_release":"false"},"msg":" 已经是最新版本"}
type WafCheckVersionResponse struct {
	Code int `json:"code"`
	Data struct {
		NeedUpdate     bool   `json:"need_update"`
		Version        string `json:"version"`
		VersionName    string `json:"version_name"`
		VersionRelease string `json:"version_release"`
	} `json:"data"`
	Msg string `json:"msg"`
}

// 测试用例 CheckVersionApi
func TestCheckVersionApi(t *testing.T) {
	// 创建一个基于 Gin 的引擎
	r := gin.Default()

	global.GWAF_RELEASE_VERSION = "111"
	r.GET("/samwaf/sysinfo/checkversion", new(WafSysInfoApi).CheckVersionApi)
	// 创建一个模拟的 HTTP 请求
	req, err := http.NewRequest(http.MethodGet, "/samwaf/sysinfo/checkversion", nil)
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
	//解析响应体
	var response WafCheckVersionResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	if err != nil {
		t.Errorf("响应体解析失败：%v", err)
	}
	expectedNeedUpdate := false
	if response.Data.NeedUpdate != expectedNeedUpdate {
		t.Errorf("期望的响应体：%t，实际响应体：%t", expectedNeedUpdate, response.Data.NeedUpdate)
	}
}
