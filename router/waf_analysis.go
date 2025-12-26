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
	router.GET("/api/v1/analysis/wafanalysisdaycountryrange", analysisApi.StatAnalysisDayCountryRangeApi)
	router.GET("/api/v1/analysis/spider", analysisApi.AnalysisSpiderRangeApi)
}
