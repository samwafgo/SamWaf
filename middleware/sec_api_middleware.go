package middleware

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
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
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
			c.Abort()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

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
