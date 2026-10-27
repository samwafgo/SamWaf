package middleware

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/wafsec"
	"bytes"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"strings"
)

// SecApi 鉴权中间件
func SecApi() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasSuffix(c.Request.URL.Path, "/api/v1/wafhost/host/diagnostic") {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10)
		}
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
			c.Abort()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// v2 通道：按报文前缀路由，不看 Content-Type。前缀不匹配的报文原样落到下面的
		// legacy 分支，旧客户端行为不变。
		if wafsec.IsTransportV2(string(bodyBytes)) {
			plain, _, err := wafsec.TransportDecrypt(string(bodyBytes))
			if err == nil {
				c.Request.Body = io.NopCloser(bytes.NewBuffer(plain))
			} else {
				// 会话密钥已失效（服务端重启/过期）：直接给出重新握手的明文信号。
				// 放原文过去会让业务层拿一段密文当参数解析，报出一个与真实原因无关的错。
				zlog.Debug("v2报文解密失败", err.Error())
				c.JSON(http.StatusOK, response.Response{
					Code: response.NEED_REHANDSHAKE,
					Data: "",
					Msg:  "会话密钥不可用，请重新握手",
				})
				c.Abort()
				return
			}
			c.Next()
			return
		}

		if c.Request.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
			decryptBytes, err := wafsec.AesDecrypt(string(bodyBytes), global.GWAF_COMMUNICATION_KEY)
			if err == nil {
				c.Request.Body = io.NopCloser(bytes.NewBuffer(decryptBytes))
			}

		} else if strings.Contains(c.Request.Header.Get("accept"), "text/event-stream") {
			decryptBytes, err := wafsec.AesDecrypt(string(bodyBytes), global.GWAF_COMMUNICATION_KEY)
			if err == nil {
				c.Request.Body = io.NopCloser(bytes.NewBuffer(decryptBytes))
			}
		} else if c.Request.Header.Get("X-Login-Type") == "mobile" && c.Request.Header.Get("Content-Type") == "application/json" {
			decryptBytes, err := wafsec.AesDecrypt(string(bodyBytes), global.GWAF_COMMUNICATION_KEY)
			if err == nil {
				c.Request.Body = io.NopCloser(bytes.NewBuffer(decryptBytes))
			} else {
				zlog.Debug("Decrypt error", err.Error())
			}

		}
		c.Next()
	}
}
