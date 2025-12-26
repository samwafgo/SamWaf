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
	router.GET("/api/v1/license/detail", api.GetDetailApi)
	router.POST("/api/v1/license/checklicense", api.CheckLicense)
	router.GET("/api/v1/license/confirm", api.ConfirmApi)
}
