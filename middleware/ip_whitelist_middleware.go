package middleware

import (
	"SamWaf/global"
	"github.com/gin-gonic/gin"
	"net"
	"net/http"
	"strings"
)

// IPWhitelist IP白名单中间件
func IPWhitelist() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		allowed := false

		allowedIPs := strings.Split(global.GWAF_IP_WHITELIST, ",")
		if global.GWAF_IP_WHITELIST == "0.0.0.0/0,::/0" {
			allowed = true
		} else if len(allowedIPs) == 0 {
			allowed = true
		} else {
			for _, ip := range allowedIPs {
				if ip == "0.0.0.0/0" || ip == "::/0" {
					allowed = true
					break
				}
				if isIPMatch(clientIP, ip) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"message": "Access denied",
			})
			return
		}

		c.Next()
	}
}

// 支持 CIDR 范围匹配，例如 "192.168.0.0/16"
func isIPMatch(clientIP, allowed string) bool {
	if _, ipNet, err := net.ParseCIDR(allowed); err == nil {
		return ipNet.Contains(net.ParseIP(clientIP))
	}
	return clientIP == allowed
}
