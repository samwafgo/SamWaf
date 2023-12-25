package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type StatRouter struct {
}

func (receiver *StatRouter) InitStatRouter(group *gin.RouterGroup) {
	statApi := api.APIGroupAPP.WafStatApi
	router := group.Group("")
	//首页数据
	router.GET("/samwaf/wafstatsumday", statApi.StatHomeSumDayApi)
	router.GET("/samwaf/wafstatsumdayrange", statApi.StatHomeSumDayRangeApi)
	router.GET("/samwaf/wafstatsumdaytopiprange", statApi.StatHomeSumDayTopIPRangeApi)
	router.GET("/samwaf/statsysinfo", statApi.StatSysinfoApi)

	//数据分析
	router.GET("/samwaf/wafanalysisdaycountryrange", statApi.StatAnalysisDayCountryRangeApi)
}
