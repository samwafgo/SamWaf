package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type LdpUrlRouter struct {
}

func (receiver *LdpUrlRouter) InitLdpUrlRouter(group *gin.RouterGroup) {
	LdpUrlRouterApi := api.APIGroupAPP.WafLdpUrlApi
	ldpUrlRouter := group.Group("")
	ldpUrlRouter.POST("/api/v1/wafhost/ldpurl/list", LdpUrlRouterApi.GetListApi)
	ldpUrlRouter.GET("/api/v1/wafhost/ldpurl/detail", LdpUrlRouterApi.GetDetailApi)
	ldpUrlRouter.POST("/api/v1/wafhost/ldpurl/add", LdpUrlRouterApi.AddApi)
	ldpUrlRouter.GET("/api/v1/wafhost/ldpurl/del", LdpUrlRouterApi.DelLdpUrlApi)
	ldpUrlRouter.POST("/api/v1/wafhost/ldpurl/edit", LdpUrlRouterApi.ModifyLdpUrlApi)
	ldpUrlRouter.POST("/api/v1/wafhost/ldpurl/batchdel", LdpUrlRouterApi.BatchDelLdpUrlApi)
	ldpUrlRouter.POST("/api/v1/wafhost/ldpurl/delall", LdpUrlRouterApi.DelAllLdpUrlApi)
}
