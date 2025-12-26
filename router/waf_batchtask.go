package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type BatchTaskRouter struct {
}

func (receiver *BatchTaskRouter) InitBatchTaskRouter(group *gin.RouterGroup) {
	BatchTaskApi := api.APIGroupAPP.WafBatchTaskApi
	router := group.Group("")
	router.POST("/api/v1/batch_task/list", BatchTaskApi.GetBatchTaskListApi)    // 列表
	router.GET("/api/v1/batch_task/detail", BatchTaskApi.GetBatchTaskDetailApi) // 详情
	router.POST("/api/v1/batch_task/add", BatchTaskApi.AddBatchTaskApi)         // 添加
	router.GET("/api/v1/batch_task/del", BatchTaskApi.DelBatchTaskApi)          // 删除
	router.POST("/api/v1/batch_task/edit", BatchTaskApi.ModifyBatchTaskApi)     // 编辑
	router.GET("/api/v1/batch_task/manual", BatchTaskApi.ManualBatchTaskApi)    // 手工执行

}
