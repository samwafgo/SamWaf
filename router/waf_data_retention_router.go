package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafDataRetentionRouter struct{}

func (receiver *WafDataRetentionRouter) InitWafDataRetentionRouter(group *gin.RouterGroup) {
	wafApi := api.APIGroupAPP.WafDataRetentionApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/dataretention/list", wafApi.GetListApi)
	router.GET("/api/v1/wafhost/dataretention/detail", wafApi.GetDetailApi)
	router.POST("/api/v1/wafhost/dataretention/edit", wafApi.ModifyApi)
}
