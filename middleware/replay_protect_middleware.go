package middleware

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model/common/response"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	replayTimeHeader  = "X-Request-Time"
	replayNonceHeader = "X-Request-Id"
	replayTimeWindow  = 5 * time.Minute
	replayNonceTTL    = 10 * time.Minute
)

func ReplayProtect() gin.HandlerFunc {
	return func(c *gin.Context) {
		if global.GCONFIG_ENABLE_REPLAY_PROTECT == 0 {
			c.Next()
			return
		}
		// 开放平台 API Key 请求跳过（Auth 中间件已在前面设置此标记）
		if v, exists := c.Get("is_openapi"); exists && v == true {
			c.Next()
			return
		}
		// WebSocket 升级跳过（Token 鉴权已足够）
		if c.GetHeader("Upgrade") == "websocket" {
			c.Next()
			return
		}

		// 校验 X-Request-Time
		tsStr := c.GetHeader(replayTimeHeader)
		nonce := c.GetHeader(replayNonceHeader)
		if tsStr == "" || nonce == "" {
			// 日志下载走 window.open，浏览器带不了自定义头，时间戳与 nonce 只能放查询串
			// （与 extractTokenStr 对同一路径的特判保持一致；仅限这条路径，其余接口仍只认头）
			if strings.HasPrefix(c.Request.URL.Path, "/api/v1/waflog/attack/download") {
				if tsStr == "" {
					tsStr = c.Query(replayTimeHeader)
				}
				if nonce == "" {
					nonce = c.Query(replayNonceHeader)
				}
			}
		}
		if tsStr == "" {
			response.FailWithMessage("请求缺少时间标头", c)
			c.Abort()
			return
		}
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			response.FailWithMessage("请求时间格式错误", c)
			c.Abort()
			return
		}
		diff := time.Now().Sub(time.Unix(ts, 0))
		if diff < -replayTimeWindow || diff > replayTimeWindow {
			response.FailWithMessage("请求已过期，请重试", c)
			c.Abort()
			return
		}

		// 校验 X-Request-Id（Nonce）
		if nonce == "" || len(nonce) < 16 || len(nonce) > 128 {
			response.FailWithMessage("请求标识无效", c)
			c.Abort()
			return
		}
		cacheKey := enums.CACHE_REPLAY_NONCE + nonce
		if global.GCACHE_WAFCACHE.IsKeyExist(cacheKey) {
			response.FailWithMessage("重复请求，已拒绝", c)
			c.Abort()
			return
		}
		global.GCACHE_WAFCACHE.SetWithTTl(cacheKey, true, replayNonceTTL)

		c.Next()
	}
}
