package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"github.com/gin-gonic/gin"
)

type WafOPlatformLogApi struct{}

// GetDetailApi 获取OpenAPI调用日志详情
func (w *WafOPlatformLogApi) GetDetailApi(c *gin.Context) {
	var req request.WafOPlatformLogDetailReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败:"+err.Error(), c)
		return
	}
	bean := wafOPlatformLogService.GetDetailApi(req)
	response.OkWithData(bean, c)
}

// GetListApi 获取OpenAPI调用日志列表
func (w *WafOPlatformLogApi) GetListApi(c *gin.Context) {
	var req request.WafOPlatformLogSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败:"+err.Error(), c)
		return
	}
	if req.PageSize == 0 {
		req.PageSize = 10
	}
	if req.PageIndex == 0 {
		req.PageIndex = 1
	}
	list, total, err := wafOPlatformLogService.GetListApi(req)
	if err != nil {
		response.FailWithMessage("查询失败", c)
		return
	}
	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "查询成功", c)
}

// DelApi 删除OpenAPI调用日志
func (w *WafOPlatformLogApi) DelApi(c *gin.Context) {
	var req request.WafOPlatformLogDelReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败:"+err.Error(), c)
		return
	}
	if err := wafOPlatformLogService.DelApi(req); err != nil {
		response.FailWithMessage("删除失败:"+err.Error(), c)
		return
	}
	response.OkWithMessage("删除成功", c)
}
