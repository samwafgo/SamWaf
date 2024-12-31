package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type SslOrderRouter struct {
}

func (receiver *SslOrderRouter) InitSslOrderRouter(group *gin.RouterGroup) {
	sslOrderApi := api.APIGroupAPP.WafSslOrderApi
	router := group.Group("")
	router.POST("/samwaf/wafhost/sslorder/list", sslOrderApi.GetListApi)
	router.GET("/samwaf/wafhost/sslorder/detail", sslOrderApi.GetDetailApi)
	router.POST("/samwaf/wafhost/sslorder/add", sslOrderApi.AddApi)
	router.GET("/samwaf/wafhost/sslorder/del", sslOrderApi.DelApi)
	router.POST("/samwaf/wafhost/sslorder/edit", sslOrderApi.ModifyApi)
}
