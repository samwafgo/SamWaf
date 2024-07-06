package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type CenterRouter struct {
}

func (receiver *CenterRouter) InitCenterRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.CenterApi
	router := group.Group("")
	router.POST("/samwaf/center/list", api.GetListApi)
	router.POST("/samwaf/center/detail", api.GetDetailApi)
}
