package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafNotifyLogApi struct{}

var wafNotifyLogService = waf_service.WafNotifyLogServiceApp

// GetListApi 获取通知日志列表
// @Summary      获取通知日志列表
// @Description  分页查询通知发送日志列表
// @Tags         通知日志
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafNotifyLogSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /notify/log/list [post]
func (w *WafNotifyLogApi) GetListApi(c *gin.Context) {
	var req request.WafNotifyLogSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafNotifyLogService.GetListApi(req)
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

// GetDetailApi 获取通知日志详情
// @Summary      获取通知日志详情
// @Description  根据ID获取单条通知日志详情
// @Tags         通知日志
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "日志ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /notify/log/detail [get]
func (w *WafNotifyLogApi) GetDetailApi(c *gin.Context) {
	var req request.WafNotifyLogDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafNotifyLogService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelApi 删除通知日志
// @Summary      删除通知日志
// @Description  根据ID删除指定通知日志记录
// @Tags         通知日志
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "日志ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /notify/log/del [get]
func (w *WafNotifyLogApi) DelApi(c *gin.Context) {
	var req request.WafNotifyLogDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafNotifyLogService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			response.OkWithMessage("删除成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
