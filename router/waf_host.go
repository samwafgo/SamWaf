package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type HostRouter struct {
}

func (receiver *HostRouter) InitHostRouter(group *gin.RouterGroup) {
	hostApi := api.APIGroupAPP.WafHostAPi
	hostRouter := group.Group("")
	hostRouter.GET("/samwaf/wafhost/host/list", hostApi.GetListApi)
	hostRouter.GET("/samwaf/wafhost/host/detail", hostApi.GetDetailApi)
	hostRouter.POST("/samwaf/wafhost/host/add", hostApi.AddApi)
	hostRouter.GET("/samwaf/wafhost/host/del", hostApi.DelHostApi)
	hostRouter.POST("/samwaf/wafhost/host/edit", hostApi.ModifyHostApi)
	hostRouter.GET("/samwaf/wafhost/host/guardstatus", hostApi.ModifyGuardStatusApi)
	hostRouter.GET("/samwaf/wafhost/host/allhost", hostApi.GetAllListApi)
}
