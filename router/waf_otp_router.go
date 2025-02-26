package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafOtpRouter struct {
}

func (receiver *WafOtpRouter) InitWafOtpRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafOtpApi
	router := group.Group("")
	router.GET("/samwaf/wafhost/otp/init", api.InitOtpApi)
	router.POST("/samwaf/wafhost/otp/bind", api.BindApi)
	router.POST("/samwaf/wafhost/otp/unbind", api.UnBindApi)
}
