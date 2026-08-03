package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type IPGroupRouter struct {
}

func (receiver *IPGroupRouter) InitIPGroupRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafIPGroupApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/ipgroup/list", api.GetListApi)
	router.GET("/api/v1/wafhost/ipgroup/options", api.GetOptionsApi) // 不分页，供黑/白名单表单下拉
	router.GET("/api/v1/wafhost/ipgroup/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/ipgroup/add", api.AddApi)
	router.POST("/api/v1/wafhost/ipgroup/edit", api.ModifyApi)
	router.GET("/api/v1/wafhost/ipgroup/refs", api.GetRefsApi) // 删除前查引用明细
	router.GET("/api/v1/wafhost/ipgroup/del", api.DelApi)
	router.POST("/api/v1/wafhost/ipgroup/validate", api.ValidateApi) // IP写法即时校验
}

type IPGroupItemRouter struct {
}

func (receiver *IPGroupItemRouter) InitIPGroupItemRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafIPGroupItemApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/ipgroupitem/list", api.GetListApi)
	router.GET("/api/v1/wafhost/ipgroupitem/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/ipgroupitem/add", api.AddApi)
	router.POST("/api/v1/wafhost/ipgroupitem/batch/add", api.BatchAddApi)
	router.POST("/api/v1/wafhost/ipgroupitem/edit", api.ModifyApi)
	router.GET("/api/v1/wafhost/ipgroupitem/del", api.DelApi)
	router.POST("/api/v1/wafhost/ipgroupitem/batch/del", api.BatchDelApi)
	router.POST("/api/v1/wafhost/ipgroupitem/delall", api.DelAllApi)
}
