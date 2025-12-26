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
	router.POST("/api/v1/wafhost/onekeymod/list", api.GetListApi)
	router.GET("/api/v1/wafhost/onekeymod/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/onekeymod/doModify", api.DoOneKeyModifyApi)
	router.GET("/api/v1/wafhost/onekeymod/del", api.DelApi)
	router.GET("/api/v1/wafhost/onekeymod/restore", api.RestoreApi)
}
