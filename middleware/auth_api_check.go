package middleware

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/service/waf_service"
	"fmt"
	"github.com/gin-gonic/gin"
	"strings"
	"time"
)

var (
	wafTokenInfoService = waf_service.WafTokenInfoServiceApp
)

// Auth 鉴权中间件
func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取请求头中 token，实际是一个完整被签名过的 token；a complete, signed token
		tokenStr := ""
		if c.Request.RequestURI == "/samwaf/ws" {
			tokenStr = c.GetHeader("Sec-WebSocket-Protocol")
		} else if strings.HasPrefix(c.Request.RequestURI, "/samwaf/waflog/attack/download") {
			tokenStr = c.Query("X-Token")
		} else {
			tokenStr = c.GetHeader("X-Token")
		}
		if tokenStr == "" {
			zlog.Debug("无token")

			response.AuthFailWithMessage("鉴权失败", c)
			c.Abort()
			return
		} else {
			//检查是否存在
			isTokenExist := global.GCACHE_WAFCACHE.IsKeyExist(enums.CACHE_TOKEN + tokenStr)
			if !isTokenExist {
				response.AuthFailWithMessage("非法口令", c)
				c.Abort()
				return
			} else {
				tokenInfo := global.GCACHE_WAFCACHE.Get(enums.CACHE_TOKEN + tokenStr).(model.TokenInfo)
				if tokenInfo.LoginIp != c.ClientIP() {
					zlog.Error(fmt.Sprintf("登录IP不一致，请求拒绝,原IP:%v 当前IP:%v", tokenInfo.LoginIp, c.ClientIP()))
					global.GCACHE_WAFCACHE.Remove(enums.CACHE_TOKEN + tokenStr)
					response.AuthFailWithMessage("本次登录IP和上次登录IP不一致需要重新登录", c)
					c.Abort()
					return
				} else {
					//刷新token时间
					global.GCACHE_WAFCACHE.SetWithTTl(enums.CACHE_TOKEN+tokenStr, tokenInfo, time.Duration(global.GCONFIG_RECORD_TOKEN_EXPIRE_MINTUTES)*time.Minute)
				}
			}
		}

		// 这里执行路由 HandlerFunc
		c.Next()
	}
}
