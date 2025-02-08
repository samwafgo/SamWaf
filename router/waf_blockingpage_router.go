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
	router.POST("/samwaf/wafhost/blockingpage/add", api.AddApi)
	router.POST("/samwaf/wafhost/blockingpage/list", api.GetListApi)
	router.GET("/samwaf/wafhost/blockingpage/detail", api.GetDetailApi)
	router.POST("/samwaf/wafhost/blockingpage/edit", api.ModifyApi)
	router.GET("/samwaf/wafhost/blockingpage/del", api.DelApi)
}
