package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafCommonRouter struct {
}

func (receiver *WafCommonRouter) InitWafCommonRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafCommonApi
	router := group.Group("")
	router.GET("/samwaf/export", api.ExportExcelApi)
	router.POST("/samwaf/import", api.ImportExcelApi)
}
