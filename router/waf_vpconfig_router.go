package router

import (
	"SamWaf/api"

	"github.com/gin-gonic/gin"
)

type WafVpConfigRouter struct {
}

func (receiver *WafVpConfigRouter) InitWafVpConfigRouter(group *gin.RouterGroup) {
	wafVpConfigApi := api.APIGroupAPP.WafVpConfigApi
	router := group.Group("")
	router.POST("/api/v1/vipconfig/updateIpWhitelist", wafVpConfigApi.UpdateIpWhitelistApi)
	router.GET("/api/v1/vipconfig/getIpWhitelist", wafVpConfigApi.GetIpWhitelistApi)
	router.POST("/api/v1/vipconfig/updateSslEnable", wafVpConfigApi.UpdateSslEnableApi)
	router.GET("/api/v1/vipconfig/getSslStatus", wafVpConfigApi.GetSslStatusApi)
	router.POST("/api/v1/vipconfig/uploadSslCert", wafVpConfigApi.UploadSslCertApi)
	router.POST("/api/v1/vipconfig/restartManager", wafVpConfigApi.RestartManagerApi)
	router.GET("/api/v1/vipconfig/getSecurityEntry", wafVpConfigApi.GetSecurityEntryApi)
	router.POST("/api/v1/vipconfig/updateSecurityEntry", wafVpConfigApi.UpdateSecurityEntryApi)
	router.GET("/api/v1/vipconfig/getNoticeTitle", wafVpConfigApi.GetNoticeTitleApi)
	router.POST("/api/v1/vipconfig/updateNoticeTitle", wafVpConfigApi.UpdateNoticeTitleApi)
	router.GET("/api/v1/vipconfig/getDomainWhitelist", wafVpConfigApi.GetDomainWhitelistApi)
	router.POST("/api/v1/vipconfig/updateDomainWhitelist", wafVpConfigApi.UpdateDomainWhitelistApi)
	router.GET("/api/v1/vipconfig/getSslForceHttps", wafVpConfigApi.GetSslForceHttpsApi)
	router.POST("/api/v1/vipconfig/updateSslForceHttps", wafVpConfigApi.UpdateSslForceHttpsApi)
	router.GET("/api/v1/vipconfig/getSslBindCert", wafVpConfigApi.GetSslBindCertApi)
	router.POST("/api/v1/vipconfig/updateSslBindCert", wafVpConfigApi.UpdateSslBindCertApi)
}
