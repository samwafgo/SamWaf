package router

import (
	"SamWaf/api"
	"SamWaf/middleware"
	"github.com/gin-gonic/gin"
)

type WafAppRouter struct{}

func (r *WafAppRouter) InitWafAppRouter(group *gin.RouterGroup) {
	appApi := api.APIGroupAPP.WafAppApi

	// 功能开关守卫：application_manage: false 时全部返回 403
	appGroup := group.Group("", middleware.AppManageEnabled())

	// 只读 / 低风险操作（无需操作密码）
	// stop 也在此组：停止已有进程属低风险，不引入新危险能力
	appGroup.POST("/api/v1/application/app/list", appApi.GetListApi)
	appGroup.GET("/api/v1/application/app/detail", appApi.GetDetailApi)
	appGroup.GET("/api/v1/application/app/status", appApi.GetStatusApi)
	appGroup.GET("/api/v1/application/app/logs", appApi.GetLogsApi)
	appGroup.GET("/api/v1/application/app/backups", appApi.GetBackupsApi)
	appGroup.GET("/api/v1/application/app/network", appApi.GetNetStatsApi)
	appGroup.POST("/api/v1/application/app/changelogs", appApi.GetChangeLogsApi)
	appGroup.POST("/api/v1/application/app/clearlogs", appApi.ClearLogsApi)
	appGroup.GET("/api/v1/application/app/stop", appApi.StopApi)

	// 高危操作子组（需操作密码）：会执行命令/写入文件/修改配置
	dangerGroup := appGroup.Group("", middleware.AppOpPasswordRequired())
	dangerGroup.GET("/api/v1/application/app/verifypwd", appApi.VerifyPasswordApi) // 仅验证密码，无副作用
	dangerGroup.POST("/api/v1/application/app/add", appApi.AddApi)
	dangerGroup.POST("/api/v1/application/app/edit", appApi.ModifyApi)
	dangerGroup.GET("/api/v1/application/app/del", appApi.DelApi)
	dangerGroup.GET("/api/v1/application/app/start", appApi.StartApi)
	dangerGroup.GET("/api/v1/application/app/restart", appApi.RestartApi)
	dangerGroup.POST("/api/v1/application/app/upload", appApi.UploadFileApi)
	dangerGroup.POST("/api/v1/application/app/upgrade", appApi.UpgradeApi)
	dangerGroup.GET("/api/v1/application/app/rollback", appApi.RollbackApi)
}
