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
	hostRouter.POST("/api/v1/wafhost/host/list", hostApi.GetListApi)
	hostRouter.GET("/api/v1/wafhost/host/detail", hostApi.GetDetailApi)
	hostRouter.POST("/api/v1/wafhost/host/add", hostApi.AddApi)
	hostRouter.GET("/api/v1/wafhost/host/del", hostApi.DelHostApi)
	hostRouter.POST("/api/v1/wafhost/host/edit", hostApi.ModifyHostApi)
	hostRouter.GET("/api/v1/wafhost/host/guardstatus", hostApi.ModifyGuardStatusApi)
	hostRouter.GET("/api/v1/wafhost/host/startstatus", hostApi.ModifyStartStatusApi)
	hostRouter.GET("/api/v1/wafhost/host/allhost", hostApi.GetAllListApi)
	hostRouter.GET("/api/v1/wafhost/host/alldomainbyhostcode", hostApi.GetDomainsByHostCodeApi)
	hostRouter.POST("/api/v1/wafhost/host/modfiyallstatus", hostApi.ModifyAllGuardStatusApi)
	hostRouter.POST("/api/v1/wafhost/host/batchcopyconfig", hostApi.BatchCopyConfigApi)

}
