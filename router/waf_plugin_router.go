package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type PluginRouter struct {
}

func (receiver *PluginRouter) InitPluginRouter(group *gin.RouterGroup) {
	apiInstance := api.APIGroupAPP.WafPluginApi
	router := group.Group("")

	// 插件管理
	router.POST("/api/v1/wafplugin/list", apiInstance.GetListApi)
	router.GET("/api/v1/wafplugin/detail", apiInstance.GetDetailApi)
	router.POST("/api/v1/wafplugin/add", apiInstance.AddApi)
	router.POST("/api/v1/wafplugin/modify", apiInstance.ModifyApi)
	router.GET("/api/v1/wafplugin/del", apiInstance.DeleteApi)
	router.POST("/api/v1/wafplugin/toggle", apiInstance.ToggleApi)

	// 系统配置
	router.GET("/api/v1/wafplugin/systemconfig/get", apiInstance.GetSystemConfigApi)
	router.POST("/api/v1/wafplugin/systemconfig/update", apiInstance.UpdateSystemConfigApi)

	// 插件日志
	router.POST("/api/v1/wafplugin/logs", apiInstance.GetPluginLogsApi)
}
