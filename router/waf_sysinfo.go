package router

import (
	"SamWaf/api"
	"SamWaf/enums"
	"SamWaf/middleware"

	"github.com/gin-gonic/gin"
)

type WebSysInfoRouter struct {
}

func (receiver *WebSysInfoRouter) InitSysInfoRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafSysInfoApi
	router := group.Group("")
	router.GET("/api/v1/sysinfo/version", api.SysVersionApi)
	router.GET("/api/v1/sysinfo/checkversion", api.CheckVersionApi)
	// N7：自升级/回滚属高危系统操作，仅系统管理员(或超管)可执行
	router.GET("/api/v1/sysinfo/update", middleware.RequireRole(enums.ROLE_SYSTEM_ADMIN), api.UpdateApi)
	router.GET("/api/v1/sysinfo/announcement", api.GetAnnouncementApi)
	router.GET("/api/v1/sysinfo/systemparams", api.SystemParamsApi)
	router.GET("/api/v1/sysinfo/rollbacklist", api.RollbackListApi)
	router.GET("/api/v1/sysinfo/rollback", middleware.RequireRole(enums.ROLE_SYSTEM_ADMIN), api.RollbackApi)
}
