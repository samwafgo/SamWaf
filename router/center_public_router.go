package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

// 不鉴权
type CenterPublicRouter struct {
}

func (receiver *CenterPublicRouter) InitCenterRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.CenterApi
	router := group.Group("")
	router.POST("/api/v1/center/update", api.UpdateApi)
}
