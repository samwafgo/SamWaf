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
	router.GET("/samwaf/sysinfo/version", api.SysVersionApi)
}
