package router

import (
	"SamWaf/api"
	"SamWaf/enums"
	"SamWaf/middleware"

	"github.com/gin-gonic/gin"
)

type WafCaServerInfoRouter struct {
}

func (receiver *WafCaServerInfoRouter) InitWafCaServerInfoRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafCaServerInfoApi

	// 读接口：任意已登录管理员可查看
	router := group.Group("")
	router.POST("/api/v1/wafhost/caserverinfo/list", api.GetListApi)
	router.GET("/api/v1/wafhost/caserverinfo/detail", api.GetDetailApi)

	// 写接口：CA 地址决定 ACME 客户端连接的目标，属系统级配置变更，限系统管理员；
	// 与 sslconfig 写接口口径一致。
	writeRouter := group.Group("")
	writeRouter.Use(middleware.RequireRole(enums.ROLE_SYSTEM_ADMIN))
	writeRouter.POST("/api/v1/wafhost/caserverinfo/add", api.AddApi)
	writeRouter.POST("/api/v1/wafhost/caserverinfo/edit", api.ModifyApi)
	writeRouter.GET("/api/v1/wafhost/caserverinfo/del", api.DelApi)
}
