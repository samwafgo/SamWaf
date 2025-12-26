package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type LogRouter struct {
}

func (receiver *LogRouter) InitLogRouter(group *gin.RouterGroup) {
	logApi := api.APIGroupAPP.WafLogAPi
	wafLogRouter := group.Group("")

	wafLogRouter.POST("/api/v1/waflog/attack/list", logApi.GetListApi)
	wafLogRouter.GET("/api/v1/waflog/attack/export", logApi.ExportDBApi)
	wafLogRouter.GET("/api/v1/waflog/attack/download", logApi.DownloadApi)
	wafLogRouter.GET("/api/v1/waflog/attack/detail", logApi.GetDetailApi)
	wafLogRouter.GET("/api/v1/waflog/attack/allsharedb", logApi.GetAllShareDbApi)
	wafLogRouter.GET("/api/v1/waflog/attack/httpcopymask", logApi.GetHttpCopyMaskApi)
	wafLogRouter.POST("/api/v1/waflog/attack/attackiplist", logApi.GetAttackIPListApi)
	wafLogRouter.GET("/api/v1/waflog/attack/alliptag", logApi.GetAllIpTagApi)
	wafLogRouter.POST("/api/v1/waflog/attack/deletetagbyname", logApi.DeleteTagByNameApi)
}
