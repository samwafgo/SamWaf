package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafSslExpireRouter struct {
}

func (receiver *WafSslExpireRouter) InitWafSslExpireRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafSslExpireApi
	router := group.Group("")
	router.POST("/samwaf/wafhost/sslexpire/add", api.AddApi)
	router.POST("/samwaf/wafhost/sslexpire/list", api.GetListApi)
	router.GET("/samwaf/wafhost/sslexpire/detail", api.GetDetailApi)
	router.POST("/samwaf/wafhost/sslexpire/edit", api.ModifyApi)
	router.GET("/samwaf/wafhost/sslexpire/del", api.DelApi)
	router.GET("/samwaf/wafhost/sslexpire/nowcheck", api.NowCheckExpireApi)
	router.GET("/samwaf/wafhost/sslexpire/sync_host", api.SyncHostApi)
}
