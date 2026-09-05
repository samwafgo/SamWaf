package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type WafHttpAuthSessionRouter struct {
}

func (receiver *WafHttpAuthSessionRouter) InitWafHttpAuthSessionRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafHttpAuthSessionApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/httpauthsession/list", api.GetListApi)
	router.GET("/api/v1/wafhost/httpauthsession/kick", api.KickApi)
	router.POST("/api/v1/wafhost/httpauthsession/kickbyuser", api.KickByUserApi)
	router.POST("/api/v1/wafhost/httpauthsession/kickall", api.KickAllApi)
}
