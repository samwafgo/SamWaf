package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafHttpAuthBaseRouter struct {
}

func (receiver *WafHttpAuthBaseRouter) InitWafHttpAuthBaseRouter(group *gin.RouterGroup) {
	api := api.APIGroupAPP.WafHttpAuthBaseApi
	router := group.Group("")
	router.POST("/api/v1/wafhost/httpauthbase/add", api.AddApi)
	router.POST("/api/v1/wafhost/httpauthbase/list", api.GetListApi)
	router.GET("/api/v1/wafhost/httpauthbase/detail", api.GetDetailApi)
	router.POST("/api/v1/wafhost/httpauthbase/edit", api.ModifyApi)
	router.GET("/api/v1/wafhost/httpauthbase/del", api.DelApi)
}
