package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type SensitiveRouter struct {
}

func (receiver *SensitiveRouter) InitSensitiveRouter(group *gin.RouterGroup) {
	SensitiveRouterApi := api.APIGroupAPP.WafSensitiveApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/sensitive/list", SensitiveRouterApi.GetListApi)
	router.GET("/api/v1/wafhost/sensitive/detail", SensitiveRouterApi.GetDetailApi)
	router.POST("/api/v1/wafhost/sensitive/add", SensitiveRouterApi.AddApi)
	router.GET("/api/v1/wafhost/sensitive/del", SensitiveRouterApi.DelSensitiveApi)
	router.POST("/api/v1/wafhost/sensitive/edit", SensitiveRouterApi.ModifySensitiveApi)
	router.POST("/api/v1/wafhost/sensitive/batch/del", SensitiveRouterApi.BatchDelSensitiveApi)
	router.POST("/api/v1/wafhost/sensitive/delall", SensitiveRouterApi.DelAllSensitiveApi)
}
