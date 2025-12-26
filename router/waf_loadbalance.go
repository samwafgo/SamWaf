package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type LoadBalanceRouter struct {
}

func (receiver *LoadBalanceRouter) InitLoadBalanceRouter(group *gin.RouterGroup) {
	loadBalanceApi := api.APIGroupAPP.WafLoadBalanceApi
	loadBalanceRouter := group.Group("")
	loadBalanceRouter.POST("/api/v1/wafhost/loadbalance/list", loadBalanceApi.GetListApi)
	loadBalanceRouter.GET("/api/v1/wafhost/loadbalance/detail", loadBalanceApi.GetDetailApi)
	loadBalanceRouter.POST("/api/v1/wafhost/loadbalance/add", loadBalanceApi.AddApi)
	loadBalanceRouter.GET("/api/v1/wafhost/loadbalance/del", loadBalanceApi.DelLoadBalanceApi)
	loadBalanceRouter.POST("/api/v1/wafhost/loadbalance/edit", loadBalanceApi.ModifyApi)
}
