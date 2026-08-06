package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type LoginHistoryRouter struct {
}

func (receiver *LoginHistoryRouter) InitLoginHistoryRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafLoginHistoryApi
	router := group.Group("")
	router.GET("/api/v1/login_history/list", api.GetListApi)
}
