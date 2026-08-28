package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type HostGroupRouter struct {
}

func (receiver *HostGroupRouter) InitHostGroupRouter(group *gin.RouterGroup) {
	hostGroupApi := api.APIGroupAPP.WafHostGroupApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/hostgroup/list", hostGroupApi.GetListApi)
	router.GET("/api/v1/wafhost/hostgroup/all", hostGroupApi.GetAllApi) //不分页，供网站列表左栏与表单下拉
	router.GET("/api/v1/wafhost/hostgroup/detail", hostGroupApi.GetDetailApi)
	router.POST("/api/v1/wafhost/hostgroup/add", hostGroupApi.AddApi)
	router.POST("/api/v1/wafhost/hostgroup/edit", hostGroupApi.ModifyApi)
	router.GET("/api/v1/wafhost/hostgroup/del", hostGroupApi.DelApi)
	router.POST("/api/v1/wafhost/hostgroup/sort", hostGroupApi.SortApi)
	router.POST("/api/v1/wafhost/hostgroup/assign", hostGroupApi.AssignApi) //批量移动网站到分组
}
