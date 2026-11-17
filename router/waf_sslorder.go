package router

import (
	"SamWaf/api"
	"SamWaf/enums"
	"SamWaf/middleware"

	"github.com/gin-gonic/gin"
)

type SslOrderRouter struct {
}

func (receiver *SslOrderRouter) InitSslOrderRouter(group *gin.RouterGroup) {
	sslOrderApi := api.APIGroupAPP.WafSslOrderApi

	// 读接口：任意已登录管理员可查看
	router := group.Group("")
	router.POST("/api/v1/wafhost/sslorder/list", sslOrderApi.GetListApi)
	router.GET("/api/v1/wafhost/sslorder/detail", sslOrderApi.GetDetailApi)

	// 写接口：发起申请/续期会向外连接 CA 并让引擎落盘挑战文件，属系统级操作，限系统管理员；
	// 与 sslconfig/caserverinfo 写接口口径一致。
	writeRouter := group.Group("")
	writeRouter.Use(middleware.RequireRole(enums.ROLE_SYSTEM_ADMIN))
	writeRouter.POST("/api/v1/wafhost/sslorder/add", sslOrderApi.AddApi)
	writeRouter.GET("/api/v1/wafhost/sslorder/del", sslOrderApi.DelApi)
	writeRouter.POST("/api/v1/wafhost/sslorder/edit", sslOrderApi.ModifyApi)
}
