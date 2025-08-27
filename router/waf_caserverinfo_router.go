package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafCaServerInfoRouter struct {
}

func (receiver *WafCaServerInfoRouter) InitWafCaServerInfoRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafCaServerInfoApi
	router := group.Group("")
	router.POST("/samwaf/wafhost/caserverinfo/add", api.AddApi)
	router.POST("/samwaf/wafhost/caserverinfo/list", api.GetListApi)
	router.GET("/samwaf/wafhost/caserverinfo/detail", api.GetDetailApi)
	router.POST("/samwaf/wafhost/caserverinfo/edit", api.ModifyApi)
	router.GET("/samwaf/wafhost/caserverinfo/del", api.DelApi)
}
