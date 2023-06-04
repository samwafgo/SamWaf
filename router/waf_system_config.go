package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type SystemConfigRouter struct {
}

func (receiver *SystemConfigRouter) InitSystemConfigRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafSystemConfigApi
	router := group.Group("")
	router.GET("/samwaf/systemconfig/list", api.GetListApi)
	router.GET("/samwaf/systemconfig/detail", api.GetDetailApi)
	router.POST("/samwaf/systemconfig/add", api.AddApi)
	router.GET("/samwaf/systemconfig/del", api.DelApi)
	router.POST("/samwaf/systemconfig/edit", api.ModifyApi)
}
