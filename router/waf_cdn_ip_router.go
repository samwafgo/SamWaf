package router

import (
	"SamWaf/api"
	"SamWaf/enums"
	"SamWaf/middleware"

	"github.com/gin-gonic/gin"
)

type CDNIPRouter struct {
}

func (receiver *CDNIPRouter) InitCDNIPRouter(group *gin.RouterGroup) {
	apiObj := api.APIGroupAPP.WafCDNIPApi

	// 读接口：任意已登录管理员可查看厂商状态/浏览回源段
	router := group.Group("")
	router.GET("/api/v1/cdnip/provider/list", apiObj.GetListApi)   // 厂商列表(脱敏)
	router.GET("/api/v1/cdnip/provider/info", apiObj.GetInfoApi)   // 单厂商详情
	router.POST("/api/v1/cdnip/provider/ranges", apiObj.RangesApi) // 分页浏览回源段(只读)

	// 写接口：开关自拉/设凭证/立即拉取 均触发对外请求或涉及凭证，限系统管理员
	writeRouter := group.Group("")
	writeRouter.Use(middleware.RequireRole(enums.ROLE_SYSTEM_ADMIN))
	writeRouter.POST("/api/v1/cdnip/provider/autofetch", apiObj.SetAutoFetchApi)           // 开/关自动拉取
	writeRouter.POST("/api/v1/cdnip/provider/credential", apiObj.SetCredentialApi)         // 设凭证(不回显)
	writeRouter.POST("/api/v1/cdnip/provider/credential/clear", apiObj.ClearCredentialApi) // 清凭证
	writeRouter.POST("/api/v1/cdnip/provider/refresh", apiObj.RefreshApi)                  // 立即拉取一次
}
