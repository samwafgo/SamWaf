package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafGPTRouter struct {
}

func (receiver *WafGPTRouter) InitGPTRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafGPTApi
	router := group.Group("")
	router.POST("/samwaf/gpt/chat", api.ChatApi)
}
