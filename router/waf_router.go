package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type OneKeyModRouter struct {
}

func (receiver *OneKeyModRouter) InitOneKeyModRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafOneKeyModApi
	router := group.Group("")
	router.POST("/samwaf/wafhost/onekeymod/list", api.GetListApi)
	router.GET("/samwaf/wafhost/onekeymod/detail", api.GetDetailApi)
	router.POST("/samwaf/wafhost/onekeymod/doModify", api.DoOneKeyModifyApi)
	router.GET("/samwaf/wafhost/onekeymod/del", api.DelApi)
}
