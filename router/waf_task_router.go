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
	router.POST("/samwaf/wafhost/task/add", api.AddApi)
	router.POST("/samwaf/wafhost/task/list", api.GetListApi)
	router.GET("/samwaf/wafhost/task/detail", api.GetDetailApi)
	router.POST("/samwaf/wafhost/task/edit", api.ModifyApi)
	router.GET("/samwaf/wafhost/task/del", api.DelApi)
	router.GET("/samwaf/wafhost/task/manual_exec", api.ManualExecuteApi)
}
