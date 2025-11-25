package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type NotifyChannelRouter struct {
}

func (receiver *NotifyChannelRouter) InitNotifyChannelRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafNotifyChannelApi
	router := group.Group("")
	router.POST("/samwaf/notify/channel/list", api.GetListApi)
	router.GET("/samwaf/notify/channel/detail", api.GetDetailApi)
	router.POST("/samwaf/notify/channel/add", api.AddApi)
	router.GET("/samwaf/notify/channel/del", api.DelApi)
	router.POST("/samwaf/notify/channel/edit", api.ModifyApi)
	router.POST("/samwaf/notify/channel/test", api.TestApi)
}
