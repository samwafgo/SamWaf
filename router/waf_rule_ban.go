package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type RuleBanRouter struct {
}

func (receiver *RuleBanRouter) InitRuleBanRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafRuleBanApi
	router := group.Group("")
	router.GET("/api/v1/wafhost/ruleban/config", api.GetConfigApi)
	router.POST("/api/v1/wafhost/ruleban/config", api.SetConfigApi)
	router.GET("/api/v1/wafhost/ruleban/baniplist", api.GetBanIpListApi)
	router.POST("/api/v1/wafhost/ruleban/removebanip", api.RemoveBanIpApi)
}
