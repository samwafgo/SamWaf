package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type SysLogRouter struct {
}

func (receiver *SysLogRouter) InitSysLogRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafSysLogApi
	router := group.Group("")
	router.GET("/samwaf/sys_log/list", api.GetListApi)
	router.GET("/samwaf/sys_log/detail", api.GetDetailApi)
}
