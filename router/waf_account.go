package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type AccountRouter struct {
}

func (receiver *AccountRouter) InitAccountRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafAccountApi
	router := group.Group("")
	router.POST("/samwaf/account/list", api.GetListApi)
	router.GET("/samwaf/account/detail", api.GetDetailApi)
	router.POST("/samwaf/account/add", api.AddApi)
	router.GET("/samwaf/account/del", api.DelAccountApi)
	router.POST("/samwaf/account/edit", api.ModifyAccountApi)
	router.POST("/samwaf/account/resetpwd", api.ResetAccountPwdApi)
}
