package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type AllowIpRouter struct {
}

func (receiver *AllowIpRouter) InitAllowIpRouter(group *gin.RouterGroup) {
	AllowIpRouterApi := api.APIGroupAPP.WafAllowIpApi
	allowIpRouter := group.Group("")
	allowIpRouter.POST("/api/v1/wafhost/ipwhite/list", AllowIpRouterApi.GetListApi)
	allowIpRouter.GET("/api/v1/wafhost/ipwhite/detail", AllowIpRouterApi.GetDetailApi)
	allowIpRouter.POST("/api/v1/wafhost/ipwhite/add", AllowIpRouterApi.AddApi)
	allowIpRouter.GET("/api/v1/wafhost/ipwhite/del", AllowIpRouterApi.DelAllowIpApi)
	allowIpRouter.POST("/api/v1/wafhost/ipwhite/edit", AllowIpRouterApi.ModifyAllowIpApi)

	allowIpRouter.POST("/api/v1/wafhost/ipwhite/batchdel", AllowIpRouterApi.BatchDelAllowIpApi)
	allowIpRouter.POST("/api/v1/wafhost/ipwhite/delall", AllowIpRouterApi.DelAllAllowIpApi)
}
