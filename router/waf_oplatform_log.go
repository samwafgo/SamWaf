package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafOPlatformLogRouter struct{}

func (receiver *WafOPlatformLogRouter) InitOPlatformLogRouter(group *gin.RouterGroup) {
	oplatformApi := api.APIGroupAPP.WafOPlatformLogApi
	router := group.Group("")
	router.POST("/api/v1/oplatform/log/list", oplatformApi.GetListApi)
	router.GET("/api/v1/oplatform/log/detail", oplatformApi.GetDetailApi)
	router.GET("/api/v1/oplatform/log/del", oplatformApi.DelApi)
}
