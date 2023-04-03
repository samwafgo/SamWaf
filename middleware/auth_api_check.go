package middleware

import (
	"SamWaf/model/common/response"
	"SamWaf/utils/zlog"
	"github.com/gin-gonic/gin"
)

// Auth 鉴权中间件
func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取请求头中 token，实际是一个完整被签名过的 token；a complete, signed token
		tokenStr := ""
		if c.Request.RequestURI == "/samwaf/ws" {
			tokenStr = c.GetHeader("Sec-WebSocket-Protocol")
		} else {
			tokenStr = c.GetHeader("X-Token")
		}
		if tokenStr == "" {
			zlog.Debug("无token")

			response.AuthFailWithMessage("鉴权失败", c)
			c.Abort()
			return
		}
		zlog.Debug("有token:" + tokenStr)
		// 将 claims 中的用户信息存储在 context 中
		//c.Set("userId", claims.UserId)

		// 这里执行路由 HandlerFunc
		c.Next()
	}
}
