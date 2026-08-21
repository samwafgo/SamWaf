package router

import (
	"SamWaf/api"
	"SamWaf/enums"
	"SamWaf/middleware"

	"github.com/gin-gonic/gin"
)

type SslConfigRouter struct {
}

func (receiver *SslConfigRouter) InitSslConfigRouter(group *gin.RouterGroup) {
	SslConfigRouterApi := api.APIGroupAPP.WafSslConfigApi

	// 读接口：任意已登录管理员可查看/浏览证书
	router := group.Group("")
	router.POST("/api/v1/sslconfig/list", SslConfigRouterApi.GetSslConfigListApi)    // 获取SSL配置列表
	router.GET("/api/v1/sslconfig/detail", SslConfigRouterApi.GetSslConfigDetailApi) // 获取SSL配置详情

	// 写接口：add/edit 可通过导出路径(issue #929)向宿主机落盘，属系统级操作，限系统管理员；
	// del 同为系统级配置变更，一并收紧。与 cdn_ip/vpconfig 写接口口径一致。
	writeRouter := group.Group("")
	writeRouter.Use(middleware.RequireRole(enums.ROLE_SYSTEM_ADMIN))
	writeRouter.POST("/api/v1/sslconfig/add", SslConfigRouterApi.AddSslConfigApi)     // 添加SSL配置
	writeRouter.POST("/api/v1/sslconfig/edit", SslConfigRouterApi.ModifySslConfigApi) // 编辑SSL配置
	writeRouter.GET("/api/v1/sslconfig/del", SslConfigRouterApi.DelSslConfigApi)      // 删除SSL配置
}
