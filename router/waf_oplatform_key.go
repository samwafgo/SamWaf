package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafOPlatformKeyRouter struct{}

func (receiver *WafOPlatformKeyRouter) InitOPlatformKeyRouter(group *gin.RouterGroup) {
	oplatformApi := api.APIGroupAPP.WafOPlatformKeyApi
	router := group.Group("")
	router.POST("/api/v1/oplatform/key/list", oplatformApi.GetListApi)
	router.GET("/api/v1/oplatform/key/detail", oplatformApi.GetDetailApi)
	router.POST("/api/v1/oplatform/key/add", oplatformApi.AddApi)
	router.POST("/api/v1/oplatform/key/edit", oplatformApi.ModifyApi)
	router.GET("/api/v1/oplatform/key/del", oplatformApi.DelApi)
	router.POST("/api/v1/oplatform/key/resetSecret", oplatformApi.ResetSecretApi)
}
