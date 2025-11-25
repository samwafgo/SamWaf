package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type NotifySubscriptionRouter struct {
}

func (receiver *NotifySubscriptionRouter) InitNotifySubscriptionRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafNotifySubscriptionApi
	router := group.Group("")
	router.POST("/samwaf/notify/subscription/list", api.GetListApi)
	router.GET("/samwaf/notify/subscription/detail", api.GetDetailApi)
	router.POST("/samwaf/notify/subscription/add", api.AddApi)
	router.GET("/samwaf/notify/subscription/del", api.DelApi)
	router.POST("/samwaf/notify/subscription/edit", api.ModifyApi)
}
