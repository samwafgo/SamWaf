package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WebSocketRouter struct {
}

func (receiver *WebSocketRouter) InitWebSocketRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafWebSocketApi
	router := group.Group("")
	router.GET("/samwaf/ws", api.WebSocketMessageApi)
}
