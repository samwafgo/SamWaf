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
	router.POST("/api/v1/wafhost/sslorder/list", sslOrderApi.GetListApi)
	router.GET("/api/v1/wafhost/sslorder/detail", sslOrderApi.GetDetailApi)
	router.POST("/api/v1/wafhost/sslorder/add", sslOrderApi.AddApi)
	router.GET("/api/v1/wafhost/sslorder/del", sslOrderApi.DelApi)
	router.POST("/api/v1/wafhost/sslorder/edit", sslOrderApi.ModifyApi)
}
