package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type StatRouter struct {
}

func (receiver *StatRouter) InitStatRouter(group *gin.RouterGroup) {
	statApi := api.APIGroupAPP.WafStatApi
	wafStatRouter := group.Group("")
	wafStatRouter.GET("/samwaf/wafstat", statApi.StatHomeApi)
}
