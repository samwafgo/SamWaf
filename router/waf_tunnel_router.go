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
	router.POST("/api/v1/tunnel/tunnel/add", api.AddApi)
	router.POST("/api/v1/tunnel/tunnel/list", api.GetListApi)
	router.GET("/api/v1/tunnel/tunnel/detail", api.GetDetailApi)
	router.POST("/api/v1/tunnel/tunnel/edit", api.ModifyApi)
	router.GET("/api/v1/tunnel/tunnel/del", api.DelApi)
	router.GET("/api/v1/tunnel/tunnel/connections", api.GetTunnelConnectionsApi)
}
