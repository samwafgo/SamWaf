package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type AntiCCRouter struct {
}

func (receiver *AntiCCRouter) InitAntiCCRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafAntiCCApi
	router := group.Group("")
	router.POST("/samwaf/wafhost/anticc/list", api.GetListApi)
	router.GET("/samwaf/wafhost/anticc/detail", api.GetDetailApi)
	router.POST("/samwaf/wafhost/anticc/add", api.AddApi)
	router.GET("/samwaf/wafhost/anticc/del", api.DelAntiCCApi)
	router.POST("/samwaf/wafhost/anticc/edit", api.ModifyAntiCCApi)
}
