package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type ThreatIPRouter struct {
}

func (receiver *ThreatIPRouter) InitThreatIPRouter(group *gin.RouterGroup) {
	apiObj := api.APIGroupAPP.WafThreatIPApi
	router := group.Group("")

	router.POST("/api/v1/threatip/channel/list", apiObj.GetListApi)    // 渠道列表
	router.GET("/api/v1/threatip/channel/detail", apiObj.GetDetailApi) // 渠道详情
	router.POST("/api/v1/threatip/channel/add", apiObj.AddApi)         // 新增渠道
	router.POST("/api/v1/threatip/channel/edit", apiObj.ModifyApi)     // 修改渠道
	router.GET("/api/v1/threatip/channel/del", apiObj.DelApi)          // 删除渠道
	router.POST("/api/v1/threatip/channel/sync", apiObj.SyncApi)       // 手动同步渠道

	router.GET("/api/v1/threatip/landed/summary", apiObj.LandedSummaryApi) // 落地汇总(订阅来源Tab)
	router.POST("/api/v1/threatip/landed/ips", apiObj.LandedIPsApi)        // 某渠道落地IP分页浏览(只读)
}
