package router

import (
	"SamWaf/api"
	"SamWaf/enums"
	"SamWaf/middleware"
	"SamWaf/model/common/response"

	"github.com/gin-gonic/gin"
)

type WafTunnelRouter struct {
}

func (receiver *WafTunnelRouter) InitWafTunnelRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafTunnelApi
	router := group.Group("")
	router.POST("/api/v1/tunnel/tunnel/add", api.AddApi)
	router.POST("/api/v1/tunnel/tunnel/list", api.GetListApi)
	router.GET("/api/v1/tunnel/tunnel/detail", api.GetDetailApi)
	router.POST("/api/v1/tunnel/tunnel/edit", api.ModifyApi)
	router.GET("/api/v1/tunnel/tunnel/del", api.DelApi)
	router.GET("/api/v1/tunnel/tunnel/connections", api.GetTunnelConnectionsApi)

	protection := group.Group("/api/v1/tunnel/tunnel/protection")
	protection.Use(func(c *gin.Context) {
		if c.GetBool("is_openapi") {
			response.ForbiddenWithMessage("隧道访问防护仅支持后台账号登录", c)
			c.Abort()
			return
		}
		c.Next()
	}, middleware.RequireRole(enums.ROLE_SECURITY_ADMIN))
	protection.GET("/detail", api.GetProtectionApi)
	protection.POST("/region", api.SaveRegionProtectionApi)
	protection.POST("/ddns", api.SaveDDNSProtectionApi)
	protection.POST("/refresh", api.RefreshDDNSProtectionApi)
}
