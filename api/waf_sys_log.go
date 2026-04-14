package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"github.com/gin-gonic/gin"
)

type WafSysLogApi struct {
}

// GetDetailApi 获取系统日志详情
// @Summary      获取系统日志详情
// @Description  根据ID获取系统操作日志详情
// @Tags         系统日志
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "日志ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /sys_log/detail [get]
func (w *WafSysLogApi) GetDetailApi(c *gin.Context) {
	var req request.WafSysLogDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafSysLogService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取系统日志列表
// @Summary      获取系统日志列表
// @Description  分页查询系统操作日志列表
// @Tags         系统日志
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafSysLogSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /sys_log/list [get]
func (w *WafSysLogApi) GetListApi(c *gin.Context) {
	var req request.WafSysLogSearchReq
	err := c.ShouldBind(&req)
	if err == nil {
		beans, total, _ := wafSysLogService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      beans,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
