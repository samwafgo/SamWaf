package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafOPlatformDocRouter struct{}

func (receiver *WafOPlatformDocRouter) InitOPlatformDocRouter(group *gin.RouterGroup) {
	docApi := api.APIGroupAPP.WafOPlatformDocApi
	router := group.Group("")
	router.GET("/api/v1/oplatform/doc/api", docApi.GetDocApi)
	router.GET("/api/v1/oplatform/doc/status", docApi.GetDocStatusApi)
}
