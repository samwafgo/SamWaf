package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type LogRouter struct {
}

func (receiver *LogRouter) InitLogRouter(group *gin.RouterGroup) {
	logApi := api.APIGroupAPP.WafLogAPi
	wafLogRouter := group.Group("")
	wafLogRouter.GET("/samwaf/waflog/attack/list", logApi.GetListApi)
	wafLogRouter.GET("/samwaf/waflog/attack/detail", logApi.GetDetailApi)
}
