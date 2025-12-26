package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafTaskRouter struct {
}

func (receiver *WafTaskRouter) InitWafTaskRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafTaskApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/task/add", api.AddApi)
	router.POST("/api/v1/wafhost/task/list", api.GetListApi)
	router.GET("/api/v1/wafhost/task/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/task/edit", api.ModifyApi)
	router.GET("/api/v1/wafhost/task/del", api.DelApi)
	router.GET("/api/v1/wafhost/task/manual_exec", api.ManualExecuteApi)
}
