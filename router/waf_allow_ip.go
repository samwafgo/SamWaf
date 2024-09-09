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
	allowIpRouter.POST("/samwaf/wafhost/ipwhite/list", AllowIpRouterApi.GetListApi)
	allowIpRouter.GET("/samwaf/wafhost/ipwhite/detail", AllowIpRouterApi.GetDetailApi)
	allowIpRouter.POST("/samwaf/wafhost/ipwhite/add", AllowIpRouterApi.AddApi)
	allowIpRouter.GET("/samwaf/wafhost/ipwhite/del", AllowIpRouterApi.DelAllowIpApi)
	allowIpRouter.POST("/samwaf/wafhost/ipwhite/edit", AllowIpRouterApi.ModifyAllowIpApi)
}
