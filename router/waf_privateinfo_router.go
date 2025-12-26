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
	router.POST("/api/v1/wafhost/privateinfo/add", api.AddApi)
	router.POST("/api/v1/wafhost/privateinfo/list", api.GetListApi)
	router.GET("/api/v1/wafhost/privateinfo/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/privateinfo/edit", api.ModifyApi)
	router.GET("/api/v1/wafhost/privateinfo/del", api.DelApi)
}
