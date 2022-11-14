package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WhiteIpRouter struct {
}

func (receiver *WhiteIpRouter) InitWhiteIpRouter(group *gin.RouterGroup) {
	WhiteIpRouterApi := api.APIGroupAPP.WafWhiteIpApi
	whiteIpRouter := group.Group("")
	whiteIpRouter.GET("/samwaf/wafhost/ipwhite/list", WhiteIpRouterApi.GetListApi)
	whiteIpRouter.GET("/samwaf/wafhost/ipwhite/detail", WhiteIpRouterApi.GetDetailApi)
	whiteIpRouter.POST("/samwaf/wafhost/ipwhite/add", WhiteIpRouterApi.AddApi)
	whiteIpRouter.GET("/samwaf/wafhost/ipwhite/del", WhiteIpRouterApi.DelWhiteIpApi)
	whiteIpRouter.POST("/samwaf/wafhost/ipwhite/edit", WhiteIpRouterApi.ModifyWhiteIpApi)
}
