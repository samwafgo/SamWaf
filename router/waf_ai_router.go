package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type WafAIRouter struct {
}

// InitWafAIRouter AI智能检测：模型管理与训练数据导出。
// 涉及模型上传（会被引擎加载）与数据导出（数据出库），属安全敏感接口，
// 应挂在仅 Token 登录可访问的路由组上。
func (receiver *WafAIRouter) InitWafAIRouter(group *gin.RouterGroup) {
	apiInstance := api.APIGroupAPP.WafAIApi
	router := group.Group("/api/v1/ai")
	{
		router.GET("/status", apiInstance.GetAIStatusApi)
		router.POST("/dashboard", apiInstance.GetAIDashboardApi)
		router.POST("/model/upload", apiInstance.UploadAIModelApi)
		router.POST("/model/reload", apiInstance.ReloadAIModelApi)
		router.POST("/model/unload", apiInstance.UnloadAIModelApi)
		router.POST("/export", apiInstance.ExportTrainDataApi)
		router.POST("/label/mark", apiInstance.MarkLabelApi)
		router.POST("/label/unmark", apiInstance.UnmarkLabelApi)
		router.POST("/label/by_uuids", apiInstance.LabelByUuidsApi)
		router.POST("/label/list", apiInstance.LabelListApi)
		router.POST("/label/batch_mark", apiInstance.BatchMarkLabelApi)
		router.POST("/label/batch_unmark", apiInstance.BatchUnmarkLabelApi)
	}
}
