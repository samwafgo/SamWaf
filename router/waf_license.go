package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafLicenseRouter struct {
}

func (receiver *WafLicenseRouter) InitLicenseRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafLicenseApi
	router := group.Group("")
	router.GET("/samwaf/license/detail", api.GetDetailApi)
	router.POST("/samwaf/license/checklicense", api.CheckLicense)
	router.GET("/samwaf/license/confirm", api.ConfirmApi)
}
