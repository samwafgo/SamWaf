package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafPrivateInfoRouter struct {
}

func (receiver *WafPrivateInfoRouter) InitWafPrivateInfoRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafPrivateInfoApi
	router := group.Group("")
	router.POST("/samwaf/wafhost/privateinfo/add", api.AddApi)
	router.POST("/samwaf/wafhost/privateinfo/list", api.GetListApi)
	router.GET("/samwaf/wafhost/privateinfo/detail", api.GetDetailApi)
	router.POST("/samwaf/wafhost/privateinfo/edit", api.ModifyApi)
	router.GET("/samwaf/wafhost/privateinfo/del", api.DelApi)
}
