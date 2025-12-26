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
	router.GET("/api/v1/wafhost/otp/init", api.InitOtpApi)
	router.POST("/api/v1/wafhost/otp/bind", api.BindApi)
	router.POST("/api/v1/wafhost/otp/unbind", api.UnBindApi)
}
