package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type HostGuardRouter struct {
}

func (receiver *HostGuardRouter) InitHostGuardRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafHostGuardApi
	router := group.Group("")

	// 状态与统计
	router.GET("/api/v1/hostguard/status", api.GetStatusApi)         // 运行状态与环境能力
	router.GET("/api/v1/hostguard/statistics", api.GetStatisticsApi) // 概览统计

	// 登录失败事件
	router.POST("/api/v1/hostguard/event/list", api.GetEventListApi)

	// 封禁账本
	router.POST("/api/v1/hostguard/ban/list", api.GetBanListApi)
	router.POST("/api/v1/hostguard/ban/release", api.ReleaseBanApi)   // 提前解封
	router.POST("/api/v1/hostguard/ban/permanent", api.PromoteBanApi) // 提升为永久
	router.POST("/api/v1/hostguard/ban/manual", api.ManualBanApi)     // 手工封禁

	// 攻击者档案
	router.POST("/api/v1/hostguard/offender/list", api.GetOffenderListApi)
	router.POST("/api/v1/hostguard/offender/reset", api.ResetOffenderApi) // 重置阶梯
	router.POST("/api/v1/hostguard/offender/del", api.DelOffenderApi)

	// 封禁阶梯
	router.GET("/api/v1/hostguard/ladder/list", api.GetLadderApi)
	router.POST("/api/v1/hostguard/ladder/save", api.SaveLadderApi)

	// 白名单
	router.POST("/api/v1/hostguard/whitelist/test", api.TestWhitelistApi) // 自测某IP会否豁免
	router.POST("/api/v1/hostguard/whitelist/add", api.AddWhitelistApi)
}
