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
	wafRuleRouter.GET("/samwaf/wafhost/rule/list", ruleApi.GetListApi)
	wafRuleRouter.GET("/samwaf/wafhost/rule/detail", ruleApi.GetDetailApi)
	wafRuleRouter.POST("/samwaf/wafhost/rule/add", ruleApi.AddApi)
	wafRuleRouter.GET("/samwaf/wafhost/rule/del", ruleApi.DelRuleApi)
	wafRuleRouter.POST("/samwaf/wafhost/rule/edit", ruleApi.ModifyRuleApi)
}
