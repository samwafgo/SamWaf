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
	router.POST("/api/v1/wafhost/caserverinfo/add", api.AddApi)
	router.POST("/api/v1/wafhost/caserverinfo/list", api.GetListApi)
	router.GET("/api/v1/wafhost/caserverinfo/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/caserverinfo/edit", api.ModifyApi)
	router.GET("/api/v1/wafhost/caserverinfo/del", api.DelApi)
}
