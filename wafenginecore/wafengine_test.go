package wafenginecore

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
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

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 在这里可以自定义 DNS 解析过程
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// 使用解析后的 IP 地址进行连接
			dialer := net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			//通过自定义nameserver获取域名解析的IP
			//ips, _ := dialer.Resolver.LookupHost(ctx, host)
			//for _, s := range ips {
			// log.Println(s)
			//}

			// 创建链接
			if host == "www.qdbinet.com" {
				ip := "127.0.0.1"
				log.Println(ip)
				log.Println(port)
				conn, err := dialer.DialContext(ctx, network, ip+":"+"81")
				if err == nil {
					return conn, nil
				}
			}

			return dialer.DialContext(ctx, network, host+":80")
		},
	}
	// 创建反向代理
	// 创建反向代理
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   "www.qdbinet.com",
	})
	proxy.Transport = transport
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
		return nil
	}
}
