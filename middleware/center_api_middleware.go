package middleware

import (
	"SamWaf/global"
	"SamWaf/service/waf_service"
	"SamWaf/utils/zlog"
	"bytes"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
	"strings"
)

var (
	centerService = waf_service.CenterServiceApp
)

// 中心管控 鉴权中间件
func CenterApi() gin.HandlerFunc {
	return func(c *gin.Context) {
		/*for key, values := range c.Request.Header {
			fmt.Printf("Header key: %s\n", key)
			for _, value := range values {
				fmt.Printf("  Value: %s\n", value)
			}
		}*/

		remoteWafUserId := c.Request.Header.Get("Remote-Waf-User-Id") //tencent@usercode
		if remoteWafUserId != "" {
			//拆分数据 tencent@usercode
			split := strings.Split(remoteWafUserId, "@")
			centerBean := centerService.GetDetailByTencentUserCode(split[0], split[1])
			if centerBean.Id != "" && c.RemoteIP() != centerBean.ClientIP {

				if global.GWAF_REG_CUR_CLIENT_COUNT > global.GWAF_REG_FREE_COUNT {

					// 停止后续的处理
					c.Abort()
					return
				}
				c.Request.Header.Set("X-Token", centerBean.ClientToken) //TODO 调试时候用 到正式的时候 这个用下面的
				c.Request.Header.Set("OPEN-X-Token", centerBean.ClientToken)
				// 构建远程服务的URL
				remoteURL := centerBean.ClientIP + ":" + centerBean.ClientPort + c.Request.URL.Path
				if c.Request.URL.RawQuery != "" {
					remoteURL = remoteURL + "?" + c.Request.URL.RawQuery
				}
				if centerBean.ClientSsl == "false" {
					remoteURL = "http://" + remoteURL
				} else {
					remoteURL = "https://" + remoteURL
				}
				// 发起代理请求
				proxyRequest(c, remoteURL)
				// 停止后续的处理
				c.Abort()
				return
				//1.读取标识，然后提取通信KEY
				//2.校验别是自己操作自己 可能会循环访问
			}
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
