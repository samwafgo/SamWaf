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
	router.POST("/api/v1/wafhost/cacherule/add", api.AddApi)
	router.POST("/api/v1/wafhost/cacherule/list", api.GetListApi)
	router.GET("/api/v1/wafhost/cacherule/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/cacherule/edit", api.ModifyApi)
	router.GET("/api/v1/wafhost/cacherule/del", api.DelApi)
}
