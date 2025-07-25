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
func (w *WafSystemMonitorApi) GetSystemMonitorApi(c *gin.Context) {
	systemInfo, err := wafSystemMonitorService.GetSystemMonitorInfo()
	if err != nil {
		response.FailWithMessage("获取系统监控信息失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(systemInfo, "获取成功", c)
}
