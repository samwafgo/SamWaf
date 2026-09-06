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
	router.GET("/api/v1/vipconfig/getManageCDNProvider", wafVpConfigApi.GetManageCDNProviderApi)
	router.GET("/api/v1/vipconfig/getCorsAllowOrigins", wafVpConfigApi.GetCorsAllowOriginsApi)
	router.GET("/api/v1/vipconfig/getSslStatus", wafVpConfigApi.GetSslStatusApi)
	router.GET("/api/v1/vipconfig/getSecurityEntry", wafVpConfigApi.GetSecurityEntryApi)
	router.GET("/api/v1/vipconfig/getNoticeTitle", wafVpConfigApi.GetNoticeTitleApi)
	router.GET("/api/v1/vipconfig/getDomainWhitelist", wafVpConfigApi.GetDomainWhitelistApi)
	router.GET("/api/v1/vipconfig/getSslForceHttps", wafVpConfigApi.GetSslForceHttpsApi)
	router.GET("/api/v1/vipconfig/getSslBindCert", wafVpConfigApi.GetSslBindCertApi)
	router.GET("/api/v1/vipconfig/localCertStatus", wafVpConfigApi.GetLocalCertStatusApi)

	// N7：写接口仅系统管理员(或超管)可操作。这些是系统级访问控制/证书/重启等高危配置，
	// 尤其含 P0-3 的 IP 白名单与可信代理网段——低权限角色(审计/安全)不得篡改。
	writeRouter := group.Group("")
	writeRouter.Use(middleware.RequireRole(enums.ROLE_SYSTEM_ADMIN))
	writeRouter.POST("/api/v1/vipconfig/updateIpWhitelist", wafVpConfigApi.UpdateIpWhitelistApi)
	writeRouter.POST("/api/v1/vipconfig/updateManageTrustedProxies", wafVpConfigApi.UpdateManageTrustedProxiesApi)
	// 只读诊断：仅回显本次请求自身的判定过程，不接受任何入参指定IP。
	// 放在系统管理员组：回显内容含代理头名(原本只在系统参数页可见)+可信网段，
	// 凑齐即可推出"如何让自己在审计日志里显示成别的IP"，不给审计/安全角色。
	writeRouter.GET("/api/v1/vipconfig/manageClientIpProbe", wafVpConfigApi.GetManageClientIPProbeApi)
	// CDN厂商快捷填充回源段(会触发对厂商官方端点的匿名拉取，故限系统管理员)
	writeRouter.GET("/api/v1/vipconfig/cdnProviderRanges", wafVpConfigApi.GetCDNProviderRangesApi)
	writeRouter.POST("/api/v1/vipconfig/updateManageCDNProvider", wafVpConfigApi.UpdateManageCDNProviderApi)
	writeRouter.POST("/api/v1/vipconfig/updateCorsAllowOrigins", wafVpConfigApi.UpdateCorsAllowOriginsApi)
	writeRouter.POST("/api/v1/vipconfig/updateSslEnable", wafVpConfigApi.UpdateSslEnableApi)
	writeRouter.POST("/api/v1/vipconfig/uploadSslCert", wafVpConfigApi.UploadSslCertApi)
	// 本地证书：与上传证书同权限——落地效果一样(都会覆盖管理端证书文件)
	writeRouter.POST("/api/v1/vipconfig/generateLocalCert", wafVpConfigApi.GenerateLocalCertApi)
	// 重建CA与清除属破坏性操作，权限同上（都会覆盖/删除管理端证书文件）
	writeRouter.POST("/api/v1/vipconfig/rotateLocalCa", wafVpConfigApi.RotateLocalCaApi)
	writeRouter.POST("/api/v1/vipconfig/clearLocalCert", wafVpConfigApi.ClearLocalCertApi)
	writeRouter.POST("/api/v1/vipconfig/restartManager", wafVpConfigApi.RestartManagerApi)
	writeRouter.POST("/api/v1/vipconfig/updateSecurityEntry", wafVpConfigApi.UpdateSecurityEntryApi)
	writeRouter.POST("/api/v1/vipconfig/updateNoticeTitle", wafVpConfigApi.UpdateNoticeTitleApi)
	writeRouter.POST("/api/v1/vipconfig/updateDomainWhitelist", wafVpConfigApi.UpdateDomainWhitelistApi)
	writeRouter.POST("/api/v1/vipconfig/updateSslForceHttps", wafVpConfigApi.UpdateSslForceHttpsApi)
	writeRouter.POST("/api/v1/vipconfig/updateSslBindCert", wafVpConfigApi.UpdateSslBindCertApi)
}
