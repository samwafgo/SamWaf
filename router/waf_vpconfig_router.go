package router

import (
	"SamWaf/api"
	"SamWaf/enums"
	"SamWaf/middleware"

	"github.com/gin-gonic/gin"
)

type WafVpConfigRouter struct {
}

func (receiver *WafVpConfigRouter) InitWafVpConfigRouter(group *gin.RouterGroup) {
	wafVpConfigApi := api.APIGroupAPP.WafVpConfigApi
	// 读接口：任意已登录管理员可查看当前配置
	router := group.Group("")
	router.GET("/api/v1/vipconfig/getIpWhitelist", wafVpConfigApi.GetIpWhitelistApi)
	router.GET("/api/v1/vipconfig/getManageTrustedProxies", wafVpConfigApi.GetManageTrustedProxiesApi)
	router.GET("/api/v1/vipconfig/getSslStatus", wafVpConfigApi.GetSslStatusApi)
	router.GET("/api/v1/vipconfig/getSecurityEntry", wafVpConfigApi.GetSecurityEntryApi)
	router.GET("/api/v1/vipconfig/getNoticeTitle", wafVpConfigApi.GetNoticeTitleApi)
	router.GET("/api/v1/vipconfig/getDomainWhitelist", wafVpConfigApi.GetDomainWhitelistApi)
	router.GET("/api/v1/vipconfig/getSslForceHttps", wafVpConfigApi.GetSslForceHttpsApi)
	router.GET("/api/v1/vipconfig/getSslBindCert", wafVpConfigApi.GetSslBindCertApi)

	// N7：写接口仅系统管理员(或超管)可操作。这些是系统级访问控制/证书/重启等高危配置，
	// 尤其含 P0-3 的 IP 白名单与可信代理网段——低权限角色(审计/安全)不得篡改。
	writeRouter := group.Group("")
	writeRouter.Use(middleware.RequireRole(enums.ROLE_SYSTEM_ADMIN))
	writeRouter.POST("/api/v1/vipconfig/updateIpWhitelist", wafVpConfigApi.UpdateIpWhitelistApi)
	writeRouter.POST("/api/v1/vipconfig/updateManageTrustedProxies", wafVpConfigApi.UpdateManageTrustedProxiesApi)
	writeRouter.POST("/api/v1/vipconfig/updateSslEnable", wafVpConfigApi.UpdateSslEnableApi)
	writeRouter.POST("/api/v1/vipconfig/uploadSslCert", wafVpConfigApi.UploadSslCertApi)
	writeRouter.POST("/api/v1/vipconfig/restartManager", wafVpConfigApi.RestartManagerApi)
	writeRouter.POST("/api/v1/vipconfig/updateSecurityEntry", wafVpConfigApi.UpdateSecurityEntryApi)
	writeRouter.POST("/api/v1/vipconfig/updateNoticeTitle", wafVpConfigApi.UpdateNoticeTitleApi)
	writeRouter.POST("/api/v1/vipconfig/updateDomainWhitelist", wafVpConfigApi.UpdateDomainWhitelistApi)
	writeRouter.POST("/api/v1/vipconfig/updateSslForceHttps", wafVpConfigApi.UpdateSslForceHttpsApi)
	writeRouter.POST("/api/v1/vipconfig/updateSslBindCert", wafVpConfigApi.UpdateSslBindCertApi)
}
