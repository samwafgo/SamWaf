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
	router.POST("/samwaf/wafhost/privategroup/add", api.AddApi)
	router.POST("/samwaf/wafhost/privategroup/list", api.GetListApi)
	router.POST("/samwaf/wafhost/privategroup/listbybelongcloud", api.GetListByBelongCloudApi)
	router.GET("/samwaf/wafhost/privategroup/detail", api.GetDetailApi)
	router.POST("/samwaf/wafhost/privategroup/edit", api.ModifyApi)
	router.GET("/samwaf/wafhost/privategroup/del", api.DelApi)
}
