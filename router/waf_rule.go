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
	wafRuleRouter.POST("/api/v1/wafhost/rule/list", ruleApi.GetListApi)
	wafRuleRouter.GET("/api/v1/wafhost/rule/detail", ruleApi.GetDetailApi)
	wafRuleRouter.POST("/api/v1/wafhost/rule/add", ruleApi.AddApi)
	wafRuleRouter.GET("/api/v1/wafhost/rule/del", ruleApi.DelRuleApi)
	wafRuleRouter.POST("/api/v1/wafhost/rule/edit", ruleApi.ModifyRuleApi)
	wafRuleRouter.POST("/api/v1/wafhost/rule/batchdel", ruleApi.BatchDelRuleApi)
	wafRuleRouter.POST("/api/v1/wafhost/rule/delall", ruleApi.DelAllRuleApi)
	wafRuleRouter.POST("/api/v1/wafhost/rule/format", ruleApi.FormatRuleApi)
	wafRuleRouter.GET("/api/v1/wafhost/rule/rulestatus", ruleApi.ModifyRuleStatusApi)
}
