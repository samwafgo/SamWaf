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
	wafLogRouter.POST("/api/v1/waflog/attack/shard/del", logApi.DelShardApi)
	wafLogRouter.GET("/api/v1/waflog/attack/httpcopymask", logApi.GetHttpCopyMaskApi)
	wafLogRouter.POST("/api/v1/waflog/attack/attackiplist", logApi.GetAttackIPListApi)
	wafLogRouter.GET("/api/v1/waflog/attack/alliptag", logApi.GetAllIpTagApi)
	wafLogRouter.POST("/api/v1/waflog/attack/deletetagbyname", logApi.DeleteTagByNameApi)
	wafLogRouter.GET("/api/v1/waflog/attack/iptagdbstatus", logApi.GetIPTagDBStatusApi)
	wafLogRouter.POST("/api/v1/waflog/attack/watchlist/add", logApi.AddIPWatchlistApi)
	wafLogRouter.POST("/api/v1/waflog/attack/watchlist/del", logApi.DelIPWatchlistApi)
	wafLogRouter.POST("/api/v1/waflog/attack/watchlist/list", logApi.GetIPWatchlistApi)

	logExportApi := api.WafLogExportAPI{}
	exportsRouter := group.Group("")
	exportsRouter.GET("/api/v1/waflog/exports/capabilities", logExportApi.Capabilities)
	exportsRouter.GET("/api/v1/waflog/exports", logExportApi.List)
	exportsRouter.POST("/api/v1/waflog/exports", logExportApi.Create)
	exportsRouter.GET("/api/v1/waflog/exports/:id", logExportApi.Get)
	exportsRouter.POST("/api/v1/waflog/exports/:id/cancel", logExportApi.Cancel)
	exportsRouter.POST("/api/v1/waflog/exports/:id/download-ticket", logExportApi.DownloadTicket)
	exportsRouter.DELETE("/api/v1/waflog/exports/:id", logExportApi.Delete)
}
