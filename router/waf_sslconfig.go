package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type SslConfigRouter struct {
}

func (receiver *SslConfigRouter) InitSslConfigRouter(group *gin.RouterGroup) {
	SslConfigRouterApi := api.APIGroupAPP.WafSslConfigApi
	router := group.Group("")
	router.POST("/samwaf/sslconfig/list", SslConfigRouterApi.GetSslConfigListApi)    // 获取SSL配置列表
	router.GET("/samwaf/sslconfig/detail", SslConfigRouterApi.GetSslConfigDetailApi) // 获取SSL配置详情
	router.POST("/samwaf/sslconfig/add", SslConfigRouterApi.AddSslConfigApi)         // 添加SSL配置
	router.GET("/samwaf/sslconfig/del", SslConfigRouterApi.DelSslConfigApi)          // 删除SSL配置
	router.POST("/samwaf/sslconfig/edit", SslConfigRouterApi.ModifySslConfigApi)     // 编辑SSL配置
}
