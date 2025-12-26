package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafFileRouter struct {
}

func (receiver *WafFileRouter) InitWafFileRouter(group *gin.RouterGroup) {
	fileApi := api.APIGroupAPP.WafFileApi
	router := group.Group("/api/v1/file")
	{
		router.GET("/data_files", fileApi.GetDataFilesApi)
		router.GET("/delete_by_id", fileApi.DeleteFileByIdApi)
	}
}
