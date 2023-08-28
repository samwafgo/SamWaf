package wafenginecore

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

func TestWafEngine_Start_WAF(t *testing.T) {

	respContentType := "text/html; charset=utf-8"
	respContentType = strings.Replace(respContentType, "; charset=utf-8", "", -1)
	println(respContentType)
	// 创建被测试的HTTP服务器
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, world!")
	}))
	defer testServer.Close()

	// 创建反向代理
	// 创建反向代理
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   "www.qdbinet.com:80",
	})
	proxy.ModifyResponse = modifyResponse()
	// 创建测试请求
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 使用httptest来捕获响应
	recorder := httptest.NewRecorder()

	// 调用被测试的处理函数
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})
	handler.ServeHTTP(recorder, req)

	// 验证代理是否正常工作
	expectedResponse := "Hello, world!\n"
	if recorder.Body.String() != expectedResponse {
		t.Errorf("Proxy response mismatch: got %v want %v",
			recorder.Body.String(), expectedResponse)
	}

}
func modifyResponse() func(*http.Response) error {
	return func(resp *http.Response) error {
		resp.Header.Set("WAF", "SamWAF")
		// 遍历头部数据
		fmt.Println("Response Headers:")
		for key, values := range resp.Header {
			fmt.Printf("%s: %s\n", key, values)
		}
		fmt.Printf("%s: %d\n", "header长度", resp.ContentLength)
		fmt.Printf("%s: %d\n", "实际长度")
		return nil
	}
}
