package api

import (
	"SamWaf/model/common/response"
	"SamWaf/service/waf_service"
	"github.com/gin-gonic/gin"
)

type WafSystemMonitorApi struct {
}

var wafSystemMonitorService = waf_service.WafSystemMonitorServiceApp

// GetSystemMonitorApi 获取系统监控信息
// @Summary      获取系统监控信息
// @Description  获取实时系统监控数据（CPU使用率、内存占用、网络流量等）
// @Tags         系统监控
// @Produce      json
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /monitor/system_info [get]
func (w *WafSystemMonitorApi) GetSystemMonitorApi(c *gin.Context) {
	systemInfo, err := wafSystemMonitorService.GetSystemMonitorInfo()
	if err != nil {
		response.FailWithMessage("获取系统监控信息失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(systemInfo, "获取成功", c)
}
