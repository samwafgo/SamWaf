package middleware

import (
	"SamWaf/global"
	"github.com/gin-gonic/gin"
	"net"
	"net/http"
	"strings"
)

// DomainWhitelist 域名白名单中间件
// 为空时不限制；非空时仅允许 Host 匹配的域名访问（忽略端口）。
func DomainWhitelist() gin.HandlerFunc {
	return func(c *gin.Context) {
		whitelist := strings.TrimSpace(global.GWAF_DOMAIN_WHITELIST)
		if whitelist == "" {
			c.Next()
			return
		}

		host := c.Request.Host
		hostname, _, err := net.SplitHostPort(host)
		if err != nil {
			hostname = host
		}

		for _, domain := range strings.Split(whitelist, ",") {
			if strings.TrimSpace(domain) == hostname {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"message": "Access denied",
		})
	}
}
