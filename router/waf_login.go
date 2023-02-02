package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type LoginRouter struct {
}

func (receiver *LoginRouter) InitLoginRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafLoginApi
	router := group.Group("")
	router.POST("/samwaf/login", api.LoginApi)
	router.POST("/samwaf/logout", api.LoginOutApi)
}
