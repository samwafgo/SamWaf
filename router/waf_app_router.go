package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafAppRouter struct{}

func (r *WafAppRouter) InitWafAppRouter(group *gin.RouterGroup) {
	appApi := api.APIGroupAPP.WafAppApi
	group.POST("/api/v1/application/app/add", appApi.AddApi)
	group.POST("/api/v1/application/app/list", appApi.GetListApi)
	group.GET("/api/v1/application/app/detail", appApi.GetDetailApi)
	group.POST("/api/v1/application/app/edit", appApi.ModifyApi)
	group.GET("/api/v1/application/app/del", appApi.DelApi)
	group.GET("/api/v1/application/app/start", appApi.StartApi)
	group.GET("/api/v1/application/app/stop", appApi.StopApi)
	group.GET("/api/v1/application/app/restart", appApi.RestartApi)
	group.GET("/api/v1/application/app/status", appApi.GetStatusApi)
	group.GET("/api/v1/application/app/logs", appApi.GetLogsApi)
	group.POST("/api/v1/application/app/clearlogs", appApi.ClearLogsApi)
	group.POST("/api/v1/application/app/upload", appApi.UploadFileApi)
	group.POST("/api/v1/application/app/upgrade", appApi.UpgradeApi)
	group.GET("/api/v1/application/app/rollback", appApi.RollbackApi)
	group.GET("/api/v1/application/app/backups", appApi.GetBackupsApi)
	group.GET("/api/v1/application/app/network", appApi.GetNetStatsApi)
}
