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
	router.GET("/samwaf/wafstatsumday", statApi.StatHomeSumDayApi)
	router.GET("/samwaf/wafstatsumdayrange", statApi.StatHomeSumDayRangeApi)
	router.GET("/samwaf/wafstatsumdaytopiprange", statApi.StatHomeSumDayTopIPRangeApi)

}
