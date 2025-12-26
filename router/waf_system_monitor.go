package router

import (
	"SamWaf/api"
	"github.com/gin-gonic/gin"
)

type WafSystemMonitorRouter struct {
}

func (s *WafSystemMonitorRouter) InitWafSystemMonitorRouter(group *gin.RouterGroup) {
	wafSystemMonitorApi := api.APIGroupAPP.WafSystemMonitorApi
	router := group.Group("")
	router.GET("/api/v1/monitor/system_info", wafSystemMonitorApi.GetSystemMonitorApi) // 获取系统监控信息

}
