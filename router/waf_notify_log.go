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
	router.POST("/api/v1/notify/log/list", api.GetListApi)
	router.GET("/api/v1/notify/log/detail", api.GetDetailApi)
	router.GET("/api/v1/notify/log/del", api.DelApi)
}
