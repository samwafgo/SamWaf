package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WhiteUrlRouter struct {
}

func (receiver *WhiteUrlRouter) InitWhiteUrlRouter(group *gin.RouterGroup) {
	WhiteUrlRouterApi := api.APIGroupAPP.WafWhiteUrlApi
	whiteUrlRouter := group.Group("")
	whiteUrlRouter.GET("/samwaf/wafhost/urlwhite/list", WhiteUrlRouterApi.GetListApi)
	whiteUrlRouter.GET("/samwaf/wafhost/urlwhite/detail", WhiteUrlRouterApi.GetDetailApi)
	whiteUrlRouter.POST("/samwaf/wafhost/urlwhite/add", WhiteUrlRouterApi.AddApi)
	whiteUrlRouter.GET("/samwaf/wafhost/urlwhite/del", WhiteUrlRouterApi.DelWhiteUrlApi)
	whiteUrlRouter.POST("/samwaf/wafhost/urlwhite/edit", WhiteUrlRouterApi.ModifyWhiteUrlApi)
}
