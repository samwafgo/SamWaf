package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type RuleRouter struct {
}

func (receiver *RuleRouter) InitRuleRouter(group *gin.RouterGroup) {
	ruleApi := api.APIGroupAPP.WafRuleAPi
	wafRuleRouter := group.Group("")
	wafRuleRouter.POST("/samwaf/wafhost/rule/list", ruleApi.GetListApi)
	wafRuleRouter.GET("/samwaf/wafhost/rule/detail", ruleApi.GetDetailApi)
	wafRuleRouter.POST("/samwaf/wafhost/rule/add", ruleApi.AddApi)
	wafRuleRouter.GET("/samwaf/wafhost/rule/del", ruleApi.DelRuleApi)
	wafRuleRouter.POST("/samwaf/wafhost/rule/edit", ruleApi.ModifyRuleApi)
	wafRuleRouter.POST("/samwaf/wafhost/rule/batchdel", ruleApi.BatchDelRuleApi)
	wafRuleRouter.POST("/samwaf/wafhost/rule/delall", ruleApi.DelAllRuleApi)
	wafRuleRouter.POST("/samwaf/wafhost/rule/format", ruleApi.FormatRuleApi)
}
