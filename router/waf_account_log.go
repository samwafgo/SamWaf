package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type AccountLogRouter struct {
}

func (receiver *AccountLogRouter) InitAccountLogRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafAccountLogApi
	router := group.Group("")
	router.GET("/api/v1/account_log/list", api.GetListApi)
	router.GET("/api/v1/account_log/detail", api.GetDetailApi)
}
