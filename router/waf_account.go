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
	router.POST("/api/v1/account/list", api.GetListApi)
	router.GET("/api/v1/account/detail", api.GetDetailApi)
	router.POST("/api/v1/account/add", api.AddApi)
	router.GET("/api/v1/account/del", api.DelAccountApi)
	router.POST("/api/v1/account/edit", api.ModifyAccountApi)
	router.POST("/api/v1/account/resetpwd", api.ResetAccountPwdApi)
	router.POST("/api/v1/account/resetotp", api.ResetAccountOTPApi)
}
