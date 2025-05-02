package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type AnalysisRouter struct {
}

func (receiver *AnalysisRouter) InitAnalysisRouter(group *gin.RouterGroup) {
	analysisApi := api.APIGroupAPP.WafAnalysisApi
	router := group.Group("")
	//数据分析
	router.GET("/samwaf/analysis/wafanalysisdaycountryrange", analysisApi.StatAnalysisDayCountryRangeApi)
	router.GET("/samwaf/analysis/spider", analysisApi.AnalysisSpiderRangeApi)
}
