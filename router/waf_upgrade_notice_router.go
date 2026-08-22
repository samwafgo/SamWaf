package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type UpgradeNoticeRouter struct {
}

// InitUpgradeNoticeRouter 升级须知：升级后告知本次变更与建议操作
//
// 只读查询 + 本机处理状态标记，不改任何防护策略与系统配置，
// 因此挂在"任意已登录角色"组（首页提示条对所有角色都要可见）。
// v2 的一键写配置属于系统管理员域，届时单独开一个受 RequireRole 保护的路由组。
func (receiver *UpgradeNoticeRouter) InitUpgradeNoticeRouter(group *gin.RouterGroup) {
	upgradeNoticeApi := api.APIGroupAPP.WafUpgradeNoticeApi
	router := group.Group("")

	router.GET("/api/v1/upgradenotice/summary", upgradeNoticeApi.GetSummaryApi)         // 顶部提示条/弹窗汇总
	router.POST("/api/v1/upgradenotice/list", upgradeNoticeApi.GetListApi)              // 列表
	router.POST("/api/v1/upgradenotice/ack", upgradeNoticeApi.AckApi)                   // 我知道了
	router.POST("/api/v1/upgradenotice/ignore", upgradeNoticeApi.IgnoreApi)             // 忽略
	router.POST("/api/v1/upgradenotice/restore", upgradeNoticeApi.RestoreApi)           // 恢复待处理
	router.POST("/api/v1/upgradenotice/popupshown", upgradeNoticeApi.PopupShownApi)     // 弹窗已展示
	router.POST("/api/v1/upgradenotice/downgradeack", upgradeNoticeApi.DowngradeAckApi) // 确认降级告警
}
