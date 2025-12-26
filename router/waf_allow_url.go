package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type AllowUrlRouter struct {
}

func (receiver *AllowUrlRouter) InitAllowUrlRouter(group *gin.RouterGroup) {
	AllowUrlRouterApi := api.APIGroupAPP.WafAllowUrlApi
	allowUrlRouter := group.Group("")
	allowUrlRouter.POST("/api/v1/wafhost/urlwhite/list", AllowUrlRouterApi.GetListApi)
	allowUrlRouter.GET("/api/v1/wafhost/urlwhite/detail", AllowUrlRouterApi.GetDetailApi)
	allowUrlRouter.POST("/api/v1/wafhost/urlwhite/add", AllowUrlRouterApi.AddApi)
	allowUrlRouter.GET("/api/v1/wafhost/urlwhite/del", AllowUrlRouterApi.DelAllowUrlApi)
	allowUrlRouter.POST("/api/v1/wafhost/urlwhite/edit", AllowUrlRouterApi.ModifyAllowUrlApi)
	// 新增批量删除路由
	allowUrlRouter.POST("/api/v1/wafhost/urlwhite/batchdel", AllowUrlRouterApi.BatchDelAllowUrlApi)
	// 新增全部删除路由
	allowUrlRouter.POST("/api/v1/wafhost/urlwhite/delall", AllowUrlRouterApi.DelAllAllowUrlApi)
}
