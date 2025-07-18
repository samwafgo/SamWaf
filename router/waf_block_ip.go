package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type BlockIpRouter struct {
}

func (receiver *BlockIpRouter) InitBlockIpRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafBlockIpApi
	router := group.Group("")
	router.POST("/samwaf/wafhost/ipblock/list", api.GetListApi)
	router.GET("/samwaf/wafhost/ipblock/detail", api.GetDetailApi)
	router.POST("/samwaf/wafhost/ipblock/add", api.AddApi)
	router.GET("/samwaf/wafhost/ipblock/del", api.DelBlockIpApi)
	router.POST("/samwaf/wafhost/ipblock/edit", api.ModifyBlockIpApi)
	router.POST("/samwaf/wafhost/ipblock/batch/del", api.BatchDelBlockIpApi)
	router.POST("/samwaf/wafhost/ipblock/delall", api.DelAllBlockIpApi)
}
