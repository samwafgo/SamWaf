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
	router.GET("/api/v1/wafstatsumday", statApi.StatHomeSumDayApi)
	router.GET("/api/v1/wafstatsumdayrange", statApi.StatHomeSumDayRangeApi)
	router.GET("/api/v1/wafstatsumdaytopiprange", statApi.StatHomeSumDayTopIPRangeApi)
	router.GET("/api/v1/statsysinfo", statApi.StatSysinfoApi)
	router.GET("/api/v1/statrumtimesysinfo", statApi.StatRumtimeSysinfoApi)
}
