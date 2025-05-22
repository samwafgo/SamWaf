package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafTunnelRouter struct {
}

func (receiver *WafTunnelRouter) InitWafTunnelRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafTunnelApi
	router := group.Group("")
	router.POST("/samwaf/tunnel/tunnel/add", api.AddApi)
	router.POST("/samwaf/tunnel/tunnel/list", api.GetListApi)
	router.GET("/samwaf/tunnel/tunnel/detail", api.GetDetailApi)
	router.POST("/samwaf/tunnel/tunnel/edit", api.ModifyApi)
	router.GET("/samwaf/tunnel/tunnel/del", api.DelApi)
	router.GET("/samwaf/tunnel/tunnel/connections", api.GetTunnelConnectionsApi)
}
