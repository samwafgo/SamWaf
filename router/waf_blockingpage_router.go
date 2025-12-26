package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafBlockingPageRouter struct {
}

func (receiver *WafBlockingPageRouter) InitWafBlockingPageRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafBlockingPageApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/blockingpage/add", api.AddApi)
	router.POST("/api/v1/wafhost/blockingpage/list", api.GetListApi)
	router.GET("/api/v1/wafhost/blockingpage/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/blockingpage/edit", api.ModifyApi)
	router.GET("/api/v1/wafhost/blockingpage/del", api.DelApi)
}
