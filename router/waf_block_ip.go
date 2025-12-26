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
	router.POST("/api/v1/wafhost/ipblock/list", api.GetListApi)
	router.GET("/api/v1/wafhost/ipblock/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/ipblock/add", api.AddApi)
	router.GET("/api/v1/wafhost/ipblock/del", api.DelBlockIpApi)
	router.POST("/api/v1/wafhost/ipblock/edit", api.ModifyBlockIpApi)
	router.POST("/api/v1/wafhost/ipblock/batch/del", api.BatchDelBlockIpApi)
	router.POST("/api/v1/wafhost/ipblock/delall", api.DelAllBlockIpApi)
}
