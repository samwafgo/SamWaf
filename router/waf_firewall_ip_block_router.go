package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type FirewallIPBlockRouter struct {
}

func (receiver *FirewallIPBlockRouter) InitFirewallIPBlockRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafFirewallIPBlockApi
	router := group.Group("")

	// 基础CRUD
	router.POST("/samwaf/firewall/ipblock/list", api.GetListApi)    // 获取列表
	router.GET("/samwaf/firewall/ipblock/detail", api.GetDetailApi) // 获取详情
	router.POST("/samwaf/firewall/ipblock/add", api.AddApi)         // 添加
	router.GET("/samwaf/firewall/ipblock/del", api.DelApi)          // 删除
	router.POST("/samwaf/firewall/ipblock/edit", api.ModifyApi)     // 编辑

	// 批量操作
	router.POST("/samwaf/firewall/ipblock/batch/add", api.BatchAddApi) // 批量添加
	router.POST("/samwaf/firewall/ipblock/batch/del", api.BatchDelApi) // 批量删除

	// 启用/禁用
	router.POST("/samwaf/firewall/ipblock/enable", api.EnableApi)   // 启用
	router.POST("/samwaf/firewall/ipblock/disable", api.DisableApi) // 禁用

	// 高级功能
	router.POST("/samwaf/firewall/ipblock/sync", api.SyncApi)                  // 同步规则
	router.POST("/samwaf/firewall/ipblock/clear/expired", api.ClearExpiredApi) // 清理过期
	router.GET("/samwaf/firewall/ipblock/statistics", api.GetStatisticsApi)    // 统计信息
}
