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
	router.POST("/api/v1/wafhost/anticc/list", api.GetListApi)
	router.GET("/api/v1/wafhost/anticc/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/anticc/add", api.AddApi)
	router.GET("/api/v1/wafhost/anticc/del", api.DelAntiCCApi)
	router.POST("/api/v1/wafhost/anticc/edit", api.ModifyAntiCCApi)
	router.GET("/api/v1/wafhost/anticc/baniplist", api.GetBanIpListApi)
	router.POST("/api/v1/wafhost/anticc/removebanip", api.RemoveCCBanIPApi)
}
