package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WebSysInfoRouter struct {
}

func (receiver *WebSysInfoRouter) InitSysInfoRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafSysInfoApi
	router := group.Group("")
	router.GET("/api/v1/sysinfo/version", api.SysVersionApi)
	router.GET("/api/v1/sysinfo/checkversion", api.CheckVersionApi)
	router.GET("/api/v1/sysinfo/update", api.UpdateApi)
	router.GET("/api/v1/sysinfo/announcement", api.GetAnnouncementApi)
}
