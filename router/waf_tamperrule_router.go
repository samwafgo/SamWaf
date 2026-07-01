package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafTamperRuleRouter struct {
}

func (receiver *WafTamperRuleRouter) InitWafTamperRuleRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafTamperRuleApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/tamperrule/add", api.AddApi)
	router.POST("/api/v1/wafhost/tamperrule/list", api.GetListApi)
	router.GET("/api/v1/wafhost/tamperrule/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/tamperrule/edit", api.ModifyApi)
	router.GET("/api/v1/wafhost/tamperrule/del", api.DelApi)
	router.GET("/api/v1/wafhost/tamperrule/relearn", api.RelearnApi)
	router.POST("/api/v1/wafhost/tamperrule/relearnbatch", api.RelearnBatchApi)
	router.POST("/api/v1/wafhost/tamperrule/extract", api.ExtractUrlsApi)
	router.POST("/api/v1/wafhost/tamperrule/addbatch", api.AddBatchApi)
	router.POST("/api/v1/wafhost/tamperrule/delbatch", api.DelBatchApi)
	router.GET("/api/v1/wafhost/tamperrule/baseline", api.GetBaselineApi)
}
