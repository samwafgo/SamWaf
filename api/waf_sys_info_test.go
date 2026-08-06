package api

import (
	"SamWaf/global"
	"SamWaf/model"
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

// 测试用例 SysRuntimeInfoApi：系统信息探测必须永远有返回，不能因为取不到某项而失败
func TestSysRuntimeInfoApi(t *testing.T) {
	r := gin.Default()
	global.GWAF_RELEASE_VERSION = "v1.0.0"
	global.GWAF_RELEASE_VERSION_NAME = "20241028"
	r.GET("/api/v1/sysinfo/runtimeinfo", new(WafSysInfoApi).SysRuntimeInfoApi)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/sysinfo/runtimeinfo", nil)
	if err != nil {
		t.Fatalf("无法创建请求：%v", err)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	t.Logf("响应体内容: %s", rec.Body.String())

	if rec.Code != http.StatusOK {
		t.Errorf("期望的状态码：%d，实际状态码：%d", http.StatusOK, rec.Code)
	}
	var response WafCheckVersionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("响应解析失败：%v", err)
	}
	if response.Code != 0 {
		t.Errorf("期望的响应码：0，实际：%v", response.Code)
	}
	// 响应体默认经通讯密钥加密，先解密再解析
	payload := response.Data
	var encrypted string
	if json.Unmarshal(response.Data, &encrypted) == nil {
		decrypted, err := wafsec.AesDecrypt(encrypted, global.GWAF_COMMUNICATION_KEY)
		if err != nil {
			t.Fatalf("响应解密失败：%v", err)
		}
		payload = decrypted
	}
	var info model.RuntimeSystemInfo
	if err := json.Unmarshal(payload, &info); err != nil {
		t.Fatalf("系统信息解析失败：%v", err)
	}
	if info.OS == "" || info.Arch == "" || info.GoVersion == "" {
		t.Errorf("编译相关信息不应为空：%+v", info)
	}
	if info.OSName == "" {
		t.Error("操作系统名称至少应有兜底值")
	}
	if info.Version != "v1.0.0" || info.VersionName != "20241028" {
		t.Errorf("软件版本信息不正确：%+v", info)
	}
	if info.ProcessUptimeSeconds < 0 {
		t.Errorf("程序运行时长不应为负：%v", info.ProcessUptimeSeconds)
	}
}

// 测试用例 CheckVersionApi
func TestCheckVersionApi(t *testing.T) {
	// 创建一个基于 Gin 的引擎
	r := gin.Default()

	//解析响应体
	var response WafCheckVersionResponse

	global.GWAF_RELEASE_VERSION_NAME = "v1.3.6"
	global.GUPDATE_VERSION_URL = "http://127.0.0.1:8111/"
	r.GET("/api/v1/sysinfo/checkversion", new(WafSysInfoApi).CheckVersionApi)
	// 创建一个模拟的 HTTP 请求
	req, err := http.NewRequest(http.MethodGet, "/api/v1/sysinfo/checkversion", nil)
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
	r.GET("/api/v1/sysinfo/checkversion", new(WafSysInfoApi).CheckVersionApi)
	// 创建一个模拟的 HTTP 请求
	req, err := http.NewRequest(http.MethodGet, "/api/v1/sysinfo/checkversion", nil)
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
