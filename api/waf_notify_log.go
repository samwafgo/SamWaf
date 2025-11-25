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
