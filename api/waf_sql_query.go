package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

type WafSqlQueryApi struct {
}

func (w *WafSqlQueryApi) ExecuteQueryApi(c *gin.Context) {
	var req request.WafSqlQueryReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		result, err := wafSqlQueryService.ExecuteQuery(req)
		if err != nil {
			response.FailWithMessage("查询失败: "+err.Error(), c)
		} else {
			response.OkWithDetailed(result, "查询成功", c)
		}
	} else {
		response.FailWithMessage("解析失败: "+err.Error(), c)
	}
}

func (w *WafSqlQueryApi) GetTableInfoApi(c *gin.Context) {
	var req request.WafDbTableInfoReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("参数解析失败: "+err.Error(), c)
		return
	}
	result, err := wafSqlQueryService.GetTableInfo(req)
	if err != nil {
		response.FailWithMessage("获取表信息失败: "+err.Error(), c)
	} else {
		response.OkWithDetailed(result, "获取成功", c)
	}
}
