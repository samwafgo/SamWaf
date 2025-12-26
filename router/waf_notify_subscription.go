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
	router.POST("/api/v1/notify/subscription/list", api.GetListApi)
	router.GET("/api/v1/notify/subscription/detail", api.GetDetailApi)
	router.POST("/api/v1/notify/subscription/add", api.AddApi)
	router.GET("/api/v1/notify/subscription/del", api.DelApi)
	router.POST("/api/v1/notify/subscription/edit", api.ModifyApi)
}
