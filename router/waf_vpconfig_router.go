package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafVpConfigRouter struct {
}

func (receiver *WafVpConfigRouter) InitWafVpConfigRouter(group *gin.RouterGroup) {
	wafVpConfigApi := api.APIGroupAPP.WafVpConfigApi
	router := group.Group("")
	router.POST("/samwaf/vipconfig/updateIpWhitelist", wafVpConfigApi.UpdateIpWhitelistApi)
	router.GET("/samwaf/vipconfig/getIpWhitelist", wafVpConfigApi.GetIpWhitelistApi)
}
