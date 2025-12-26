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
	router.GET("/api/v1/sys_log/list", api.GetListApi)
	router.GET("/api/v1/sys_log/detail", api.GetDetailApi)
}
