package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type EngineRouter struct {
}

func (receiver *EngineRouter) InitEngineRouter(group *gin.RouterGroup) {
	engineApi := api.APIGroupAPP.WafEngineApi
	wafEngineRouter := group.Group("")
	wafEngineRouter.GET("/api/v1/resetWAF", engineApi.ResetWaf)

}
