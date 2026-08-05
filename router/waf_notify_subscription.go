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

	// 精细化配置与调试（issue #822）
	router.POST("/api/v1/notify/subscription/config", api.SaveConfigApi)
	router.POST("/api/v1/notify/subscription/batchconfig", api.BatchConfigApi)
	router.POST("/api/v1/notify/subscription/preview", api.PreviewApi)
	router.POST("/api/v1/notify/subscription/test", api.TestApi)
	router.POST("/api/v1/notify/subscription/dryrun", api.DryRunApi)
	router.GET("/api/v1/notify/subscription/templatevars", api.TemplateVarsApi)
	router.GET("/api/v1/notify/globalthrottle", api.GetGlobalThrottleApi)
	router.POST("/api/v1/notify/globalthrottle/update", api.UpdateGlobalThrottleApi)
}
