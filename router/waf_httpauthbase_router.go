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
	router.POST("/samwaf/wafhost/httpauthbase/add", api.AddApi)
	router.POST("/samwaf/wafhost/httpauthbase/list", api.GetListApi)
	router.GET("/samwaf/wafhost/httpauthbase/detail", api.GetDetailApi)
	router.POST("/samwaf/wafhost/httpauthbase/edit", api.ModifyApi)
	router.GET("/samwaf/wafhost/httpauthbase/del", api.DelApi)
}
