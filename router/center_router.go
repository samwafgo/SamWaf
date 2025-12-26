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
	router.POST("/api/v1/center/list", api.GetListApi)
	router.POST("/api/v1/center/detail", api.GetDetailApi)
}
