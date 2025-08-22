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
	ldpUrlRouter.POST("/samwaf/wafhost/ldpurl/list", LdpUrlRouterApi.GetListApi)
	ldpUrlRouter.GET("/samwaf/wafhost/ldpurl/detail", LdpUrlRouterApi.GetDetailApi)
	ldpUrlRouter.POST("/samwaf/wafhost/ldpurl/add", LdpUrlRouterApi.AddApi)
	ldpUrlRouter.GET("/samwaf/wafhost/ldpurl/del", LdpUrlRouterApi.DelLdpUrlApi)
	ldpUrlRouter.POST("/samwaf/wafhost/ldpurl/edit", LdpUrlRouterApi.ModifyLdpUrlApi)
	ldpUrlRouter.POST("/samwaf/wafhost/ldpurl/batchdel", LdpUrlRouterApi.BatchDelLdpUrlApi)
	ldpUrlRouter.POST("/samwaf/wafhost/ldpurl/delall", LdpUrlRouterApi.DelAllLdpUrlApi)
}
