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

	// 流式对话：走 SSE 中间件
	streamRouter := group.Group("")
	streamRouter.Use(middleware.StreamMiddleware())
	streamRouter.POST("/api/v1/gpt/chat", api.ChatApi)

	// 普通 JSON 接口：GPT 参数的读取/保存（不走流式中间件）
	router := group.Group("")
	router.GET("/api/v1/gpt/config", api.GetGptConfigApi)
	router.POST("/api/v1/gpt/config/save", api.SaveGptConfigApi)
}
