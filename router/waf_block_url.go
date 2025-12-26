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
	router.POST("/api/v1/wafhost/urlblock/list", api.GetListApi)
	router.GET("/api/v1/wafhost/urlblock/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/urlblock/add", api.AddApi)
	router.GET("/api/v1/wafhost/urlblock/del", api.DelBlockUrlApi)
	router.POST("/api/v1/wafhost/urlblock/edit", api.ModifyBlockUrlApi)
	router.POST("/api/v1/wafhost/urlblock/batchdel", api.BatchDelBlockUrlApi)
	router.POST("/api/v1/wafhost/urlblock/delall", api.DelAllBlockUrlApi)
}
