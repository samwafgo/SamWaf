package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafCacheRuleRouter struct {
}

func (receiver *WafCacheRuleRouter) InitWafCacheRuleRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafCacheRuleApi
	router := group.Group("")
	router.POST("/samwaf/wafhost/cacherule/add", api.AddApi)
	router.POST("/samwaf/wafhost/cacherule/list", api.GetListApi)
	router.GET("/samwaf/wafhost/cacherule/detail", api.GetDetailApi)
	router.POST("/samwaf/wafhost/cacherule/edit", api.ModifyApi)
	router.GET("/samwaf/wafhost/cacherule/del", api.DelApi)
}
