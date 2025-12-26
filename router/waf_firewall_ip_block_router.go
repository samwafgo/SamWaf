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
	router.POST("/api/v1/firewall/ipblock/list", api.GetListApi)    // 获取列表
	router.GET("/api/v1/firewall/ipblock/detail", api.GetDetailApi) // 获取详情
	router.POST("/api/v1/firewall/ipblock/add", api.AddApi)         // 添加
	router.GET("/api/v1/firewall/ipblock/del", api.DelApi)          // 删除
	router.POST("/api/v1/firewall/ipblock/edit", api.ModifyApi)     // 编辑

	// 批量操作
	router.POST("/api/v1/firewall/ipblock/batch/add", api.BatchAddApi) // 批量添加
	router.POST("/api/v1/firewall/ipblock/batch/del", api.BatchDelApi) // 批量删除

	// 启用/禁用
	router.POST("/api/v1/firewall/ipblock/enable", api.EnableApi)   // 启用
	router.POST("/api/v1/firewall/ipblock/disable", api.DisableApi) // 禁用

	// 高级功能
	router.POST("/api/v1/firewall/ipblock/sync", api.SyncApi)                  // 同步规则
	router.POST("/api/v1/firewall/ipblock/clear/expired", api.ClearExpiredApi) // 清理过期
	router.GET("/api/v1/firewall/ipblock/statistics", api.GetStatisticsApi)    // 统计信息
}
