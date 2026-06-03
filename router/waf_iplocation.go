package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type IPLocationRouter struct {
}

func (receiver *IPLocationRouter) InitIPLocationRouter(group *gin.RouterGroup) {
	apiInstance := api.APIGroupAPP.WafIPLocationApi
	router := group.Group("/api/v1/iplocation")
	{
		router.GET("/status", apiInstance.GetIPDBStatusApi)
		router.GET("/config", apiInstance.GetIPDBConfigApi)
		router.POST("/config/save", apiInstance.SaveIPDBConfigApi)
		router.POST("/upload", apiInstance.UploadIPDBFileApi)
		router.POST("/reload", apiInstance.ReloadIPDBApi)
		router.POST("/test", apiInstance.TestIPLookupApi)
	}
}
