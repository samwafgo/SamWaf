package middleware

import (
	"SamWaf/global"
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"
)

// AppManageEnabled 检查应用管理功能是否已在配置中开启
func AppManageEnabled() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !global.GWAF_CAN_APP_MANAGE {
			c.JSON(http.StatusForbidden, gin.H{
				"code": 403,
				"msg":  "应用管理功能未开启，请在 conf/config.yml 中设置 application_manage: true 后重启",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// AppOpPasswordRequired 高危操作要求请求头 X-App-Op-Password 与配置值匹配
// fail-closed：GWAF_APP_OP_PASSWORD 为空时一律拒绝
func AppOpPasswordRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		provided := c.GetHeader("X-App-Op-Password")
		expected := global.GWAF_APP_OP_PASSWORD
		if expected == "" || !safeEqual(expected, provided) {
			// 401 而非 403：前端可区分「密码错误」与「功能未开启」，避免触发全局 403 接管页面
			c.JSON(http.StatusUnauthorized, gin.H{
				"code": -2,
				"msg":  "应用操作密码错误或未设置",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// safeEqual 使用常量时间比较，防止时序攻击
func safeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
