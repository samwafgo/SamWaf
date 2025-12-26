package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafPrivateGroupRouter struct {
}

func (receiver *WafPrivateGroupRouter) InitWafPrivateGroupRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafPrivateGroupApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/privategroup/add", api.AddApi)
	router.POST("/api/v1/wafhost/privategroup/list", api.GetListApi)
	router.POST("/api/v1/wafhost/privategroup/listbybelongcloud", api.GetListByBelongCloudApi)
	router.GET("/api/v1/wafhost/privategroup/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/privategroup/edit", api.ModifyApi)
	router.GET("/api/v1/wafhost/privategroup/del", api.DelApi)
}
