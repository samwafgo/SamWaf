package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type LoginRouter struct {
}
type LoginOutRouter struct {
}

func (receiver *LoginRouter) InitLoginRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafLoginApi
	router := group.Group("")
	router.POST("/samwaf/public/login", api.LoginApi)
}
func (receiver *LoginOutRouter) InitLoginOutRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafLoginApi
	router := group.Group("")
	router.POST("/samwaf/logout", api.LoginOutApi)
}
