package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafHostPathRuleRouter struct{}

func (r *WafHostPathRuleRouter) InitWafHostPathRuleRouter(group *gin.RouterGroup) {
	a := api.APIGroupAPP.WafHostPathRuleApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/pathrule/add", a.AddApi)
	router.POST("/api/v1/wafhost/pathrule/list", a.GetListApi)
	router.GET("/api/v1/wafhost/pathrule/detail", a.GetDetailApi)
	router.POST("/api/v1/wafhost/pathrule/edit", a.ModifyApi)
	router.GET("/api/v1/wafhost/pathrule/del", a.DelApi)
}
