package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type HostConnRouter struct {
}

func (receiver *HostConnRouter) InitHostConnRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafHostConnApi
	router := group.Group("")

	router.POST("/api/v1/hostconn/list", api.GetListApi)      // 连接列表
	router.GET("/api/v1/hostconn/summary", api.GetSummaryApi) // 汇总卡片
	router.GET("/api/v1/hostconn/refresh", api.RefreshApi)    // 强制刷新快照
	router.POST("/api/v1/hostconn/block", api.BlockApi)       // 一键封禁来源IP
}
