package api

import (
	"SamWaf/global"
	"SamWaf/wafsec"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 响应体：{"message":"H       ello, World!"}，实际响应体：{"code":0,"data":{"need_update":false,"versi       on":"555","version_name":"1.0","version_release":"false"},"msg":" 已经是最新版本"}
type WafCheckVersionResponse struct {
	Code int             `json:"code"`
	Data json.RawMessage `json:"data"`
	Msg  string          `json:"msg"`
}
type ComplexData struct {
	NeedUpdate     bool   `json:"need_update"`
	Version        string `json:"version"`
	VersionName    string `json:"version_name"`
	VersionRelease string `json:"version_release"`
}

// 测试用例 CheckVersionApi
func TestCheckVersionApi(t *testing.T) {
	// 创建一个基于 Gin 的引擎
	r := gin.Default()

	//解析响应体
	var response WafCheckVersionResponse

	global.GWAF_RELEASE_VERSION_NAME = "v1.3.6"
	global.GUPDATE_VERSION_URL = "http://127.0.0.1:8111/"
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
	t.Logf("响应体内容: %s", rec.Body.String())

	// 检查响应状态码是否为 200
	if rec.Code != http.StatusOK {
		t.Errorf("期望的状态码：%d，实际状态码：%d", http.StatusOK, rec.Code)
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Errorf("复杂结构体解析失败：%v", err)
	}
	if response.Code != -1 {
		t.Errorf("期望的响应体：%v，实际响应体：%v", "-1", response.Code)
	}

}

// 测试用例 CheckVersionApi
func TestCheckVersionNeedUploadApi(t *testing.T) {
	// 创建一个基于 Gin 的引擎
	r := gin.Default()

	//解析响应体
	var response WafCheckVersionResponse

	global.GWAF_RELEASE_VERSION_NAME = "v1.0.6"
	global.GUPDATE_VERSION_URL = "http://127.0.0.1:8111/"
	global.GWAF_RUNTIME_WIN7_VERSION = "true"
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
	t.Logf("响应体内容: %s", rec.Body.String())

	// 检查响应状态码是否为 200
	if rec.Code != http.StatusOK {
		t.Errorf("期望的状态码：%d，实际状态码：%d", http.StatusOK, rec.Code)
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Errorf("复杂结构体解析失败：%v", err)
	}
	if response.Code < 0 {
		t.Errorf("期望的响应体：%v，实际响应体：%v", "大于0", response.Code)
	}
	// 判断 data 是简单字符串还是复杂结构体
	var dataString string
	if json.Unmarshal(response.Data, &dataString) == nil {
		// data 是字符串
		decryptedData, err := wafsec.AesDecrypt(dataString, global.GWAF_COMMUNICATION_KEY)
		if err != nil {
			t.Errorf("失败：%v", err)
			return
		}

		//JSON 数据
		var complexData ComplexData
		if err := json.Unmarshal(decryptedData, &complexData); err != nil {
			t.Errorf("数据解析失败：%v", err)
		} else {
			// 继续检查复杂结构体内容
			expectedNeedUpdate := false
			if complexData.NeedUpdate != expectedNeedUpdate {
				t.Errorf("期望的 NeedUpdate 值：%t，实际值：%t", expectedNeedUpdate, complexData.NeedUpdate)
			}
		}
	}

}
