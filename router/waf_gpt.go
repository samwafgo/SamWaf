package router

import (
	"SamWaf/api"
	"SamWaf/middleware"
	"github.com/gin-gonic/gin"
)

type WafGPTRouter struct {
}

func (receiver *WafGPTRouter) InitGPTRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafGPTApi
	router := group.Group("")
	router.Use(middleware.StreamMiddleware())
	router.POST("/api/v1/gpt/chat", api.ChatApi)
}
