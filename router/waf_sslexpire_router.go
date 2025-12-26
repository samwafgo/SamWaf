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
	router.POST("/api/v1/wafhost/sslexpire/add", api.AddApi)
	router.POST("/api/v1/wafhost/sslexpire/list", api.GetListApi)
	router.GET("/api/v1/wafhost/sslexpire/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/sslexpire/edit", api.ModifyApi)
	router.GET("/api/v1/wafhost/sslexpire/del", api.DelApi)
	router.GET("/api/v1/wafhost/sslexpire/nowcheck", api.NowCheckExpireApi)
	router.GET("/api/v1/wafhost/sslexpire/sync_host", api.SyncHostApi)
}
