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
	router.POST("/samwaf/wafhost/sensitive/list", SensitiveRouterApi.GetListApi)
	router.GET("/samwaf/wafhost/sensitive/detail", SensitiveRouterApi.GetDetailApi)
	router.POST("/samwaf/wafhost/sensitive/add", SensitiveRouterApi.AddApi)
	router.GET("/samwaf/wafhost/sensitive/del", SensitiveRouterApi.DelSensitiveApi)
	router.POST("/samwaf/wafhost/sensitive/edit", SensitiveRouterApi.ModifySensitiveApi)
	router.POST("/samwaf/wafhost/sensitive/batch/del", SensitiveRouterApi.BatchDelSensitiveApi)
	router.POST("/samwaf/wafhost/sensitive/delall", SensitiveRouterApi.DelAllSensitiveApi)
}
