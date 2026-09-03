package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type AntiCCRuleRouter struct {
}

func (receiver *AntiCCRuleRouter) InitAntiCCRuleRouter(group *gin.RouterGroup) {
	apiGroup := api.APIGroupAPP.WafAntiCCRuleApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/anticcrule/list", apiGroup.GetListApi)
	router.GET("/api/v1/wafhost/anticcrule/detail", apiGroup.GetDetailApi)
	router.POST("/api/v1/wafhost/anticcrule/add", apiGroup.AddApi)
	router.POST("/api/v1/wafhost/anticcrule/edit", apiGroup.ModifyApi)
	router.GET("/api/v1/wafhost/anticcrule/del", apiGroup.DelApi)
	router.POST("/api/v1/wafhost/anticcrule/toggle", apiGroup.ToggleApi)
	router.POST("/api/v1/wafhost/anticcrule/sort", apiGroup.SortApi)
	router.GET("/api/v1/wafhost/anticcrule/captchaoverview", apiGroup.GetCaptchaOverviewApi)
	router.POST("/api/v1/wafhost/anticcrule/threshold/recommend", apiGroup.RecommendThresholdApi)
	router.GET("/api/v1/wafhost/anticcrule/hits", apiGroup.GetHitsApi)
	router.POST("/api/v1/wafhost/anticcrule/emergency", apiGroup.SetEmergencyApi)
	router.GET("/api/v1/wafhost/anticcrule/emergency/status", apiGroup.GetEmergencyStatusApi)
}
