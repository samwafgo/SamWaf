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
	router.POST("/api/v1/systemconfig/list", api.GetListApi)
	router.GET("/api/v1/systemconfig/detail", api.GetDetailApi)
	router.GET("/api/v1/systemconfig/getdetailByItem", api.GetDetailByItemApi)
	router.POST("/api/v1/systemconfig/add", api.AddApi)
	router.GET("/api/v1/systemconfig/del", api.DelApi)
	router.POST("/api/v1/systemconfig/edit", api.ModifyApi)
}
