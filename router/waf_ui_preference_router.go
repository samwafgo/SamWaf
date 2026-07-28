package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type WafUIPreferenceRouter struct {
}

func (receiver *WafUIPreferenceRouter) InitWafUIPreferenceRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafUIPreferenceApi
	router := group.Group("")
	router.GET("/api/v1/uipreference/get", api.GetApi)
	router.POST("/api/v1/uipreference/save", api.SaveApi)
}
