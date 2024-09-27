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
	loadBalanceRouter.POST("/samwaf/wafhost/loadbalance/list", loadBalanceApi.GetListApi)
	loadBalanceRouter.GET("/samwaf/wafhost/loadbalance/detail", loadBalanceApi.GetDetailApi)
	loadBalanceRouter.POST("/samwaf/wafhost/loadbalance/add", loadBalanceApi.AddApi)
	loadBalanceRouter.GET("/samwaf/wafhost/loadbalance/del", loadBalanceApi.DelLoadBalanceApi)
	loadBalanceRouter.POST("/samwaf/wafhost/loadbalance/edit", loadBalanceApi.ModifyApi)
}
