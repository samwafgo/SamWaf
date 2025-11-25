package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type NotifyLogRouter struct {
}

func (receiver *NotifyLogRouter) InitNotifyLogRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafNotifyLogApi
	router := group.Group("")
	router.POST("/samwaf/notify/log/list", api.GetListApi)
	router.GET("/samwaf/notify/log/detail", api.GetDetailApi)
	router.GET("/samwaf/notify/log/del", api.DelApi)
}
