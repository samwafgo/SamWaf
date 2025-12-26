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
	router.POST("/api/v1/notify/channel/list", api.GetListApi)
	router.GET("/api/v1/notify/channel/detail", api.GetDetailApi)
	router.POST("/api/v1/notify/channel/add", api.AddApi)
	router.GET("/api/v1/notify/channel/del", api.DelApi)
	router.POST("/api/v1/notify/channel/edit", api.ModifyApi)
	router.POST("/api/v1/notify/channel/test", api.TestApi)
}
