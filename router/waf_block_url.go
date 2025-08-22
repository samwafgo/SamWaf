package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type BlockUrlRouter struct {
}

func (receiver *BlockUrlRouter) InitBlockUrlRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafBlockUrlApi
	router := group.Group("")
	router.POST("/samwaf/wafhost/urlblock/list", api.GetListApi)
	router.GET("/samwaf/wafhost/urlblock/detail", api.GetDetailApi)
	router.POST("/samwaf/wafhost/urlblock/add", api.AddApi)
	router.GET("/samwaf/wafhost/urlblock/del", api.DelBlockUrlApi)
	router.POST("/samwaf/wafhost/urlblock/edit", api.ModifyBlockUrlApi)
	router.POST("/samwaf/wafhost/urlblock/batchdel", api.BatchDelBlockUrlApi)
	router.POST("/samwaf/wafhost/urlblock/delall", api.DelAllBlockUrlApi)
}
