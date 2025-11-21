package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type IPFailureRouter struct {
}

func (receiver *IPFailureRouter) InitIPFailureRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafIPFailureApi
	router := group.Group("")
	router.GET("/samwaf/wafhost/ipfailure/config", api.GetConfigApi)
	router.POST("/samwaf/wafhost/ipfailure/config", api.SetConfigApi)
	router.GET("/samwaf/wafhost/ipfailure/baniplist", api.GetBanIpListApi)
	router.POST("/samwaf/wafhost/ipfailure/removebanip", api.RemoveIPFailureBanIPApi)
}
