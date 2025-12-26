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
	router.GET("/api/v1/export", api.ExportExcelApi)
	router.POST("/api/v1/import", api.ImportExcelApi)
	//心跳数据
	router.GET("/api/v1/heartbeat", api.HeartbeatApi)
}
