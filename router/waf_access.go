package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type AccessAccountRouter struct {
}

func (receiver *AccessAccountRouter) InitAccessAccountRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafAccessAccountApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/accessaccount/list", api.GetListApi)
	router.GET("/api/v1/wafhost/accessaccount/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/accessaccount/add", api.AddApi)
	router.POST("/api/v1/wafhost/accessaccount/edit", api.ModifyApi)
	router.POST("/api/v1/wafhost/accessaccount/resetpwd", api.ResetPwdApi)
	router.GET("/api/v1/wafhost/accessaccount/del", api.DelApi)
	router.GET("/api/v1/wafhost/accessaccount/otp/init", api.OtpInitApi)
	router.POST("/api/v1/wafhost/accessaccount/otp/bind", api.OtpBindApi)
	router.POST("/api/v1/wafhost/accessaccount/otp/unbind", api.OtpUnbindApi)
}

type AccessConfigRouter struct {
}

func (receiver *AccessConfigRouter) InitAccessConfigRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafAccessConfigApi
	router := group.Group("")
	router.GET("/api/v1/wafhost/accessconfig/detail", api.GetDetailApi)
	router.GET("/api/v1/wafhost/accessconfig/hostoptions", api.GetCenterHostOptionsApi)
	router.POST("/api/v1/wafhost/accessconfig/save", api.SaveApi)
	router.POST("/api/v1/wafhost/accessconfig/regenerate_secret", api.RegenerateSecretApi)
}

type AccessSessionRouter struct {
}

func (receiver *AccessSessionRouter) InitAccessSessionRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafAccessSessionApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/accesssession/list", api.GetListApi)
	router.GET("/api/v1/wafhost/accesssession/kick", api.KickApi)
	router.POST("/api/v1/wafhost/accesssession/kickbyaccount", api.KickByAccountApi)
	router.GET("/api/v1/wafhost/accesssession/kickall", api.KickAllApi)
}

type AccessAuditRouter struct {
}

func (receiver *AccessAuditRouter) InitAccessAuditRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafAccessAuditApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/accessaudit/list", api.GetListApi)
}
