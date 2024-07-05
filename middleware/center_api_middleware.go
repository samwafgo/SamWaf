package middleware

import (
	"SamWaf/utils/zlog"
	"bytes"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
	"strings"
)

// 中心管控 鉴权中间件
func CenterApi() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 检查请求的URL是否包含需要代理的路径前缀
		if strings.HasPrefix(c.Request.URL.Path, "/samwaf/wafhost/host/allhost") && c.RemoteIP() == "127.0.0.1" {
			zlog.Debug("当前访问人IP" + c.RemoteIP())
			//1.读取标识，然后提取通信KEY
			//2.校验别是自己操作自己 可能会循环访问
			c.Request.Header.Set("X-Token", "f0661bb70075c66a4375ead94a204c67")
			// 构建远程服务的URL
			remoteURL := "http://82.156.235.106:26666" + c.Request.URL.Path
			// 发起代理请求
			proxyRequest(c, remoteURL)
			// 停止后续的处理
			c.Abort()
			return
		}
		// 如果不需要代理，继续处理请求
		c.Next()
	}
}

// proxyRequest 发起一个到远程服务的请求，并将响应返回给客户端
func proxyRequest(c *gin.Context, remoteURL string) {
	// 读取请求体
	bodyBytes, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		zlog.Error("Error reading request body: %v", err)
		c.String(http.StatusInternalServerError, "Error reading request body")
		return
	}
	// 重置请求体，以便后续的使用
	c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	// 创建一个新的HTTP请求
	req, err := http.NewRequest(c.Request.Method, remoteURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		zlog.Error("Error creating new request: %v", err)
		c.String(http.StatusInternalServerError, "Error creating new request")
		return
	}

	// 设置请求头
	req.Header = c.Request.Header

	// 发起请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		zlog.Error("Error sending request to remote service: %v", err)
		c.String(http.StatusInternalServerError, "Error sending request to remote service")
		return
	}
	// 延迟关闭响应体
	defer resp.Body.Close()

	// 读取响应体
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		zlog.Error("Error reading response body: %v", err)
		c.String(http.StatusInternalServerError, "Error reading response body")
		return
	}

	// 设置响应状态码
	c.Status(resp.StatusCode)

	// 设置响应头
	for k, v := range resp.Header {
		c.Header(k, strings.Join(v, ";"))
	}

	// 设置响应体
	c.String(http.StatusOK, string(respBody))
}
