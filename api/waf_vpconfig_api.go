package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
	"SamWaf/wafconfig"
	"github.com/gin-gonic/gin"
)

type WafVpConfigApi struct {
}

// UpdateIpWhitelistApi 更新IP白名单配置
func (w *WafVpConfigApi) UpdateIpWhitelistApi(c *gin.Context) {
	var req request.WafVpConfigIpWhitelistUpdateReq
	err := c.ShouldBindJSON(&req)
	if err == nil {

		// 调用配置文件更新函数
		err = wafconfig.UpdateIpWhitelist(req.IpWhitelist)
		if err != nil {
			response.FailWithMessage("更新IP白名单失败: "+err.Error(), c)
		} else {
			response.OkWithMessage("更新IP白名单成功", c)
		}
	} else {
		response.FailWithMessage("解析请求失败", c)
	}
}

// GetIpWhitelistApi 获取IP白名单配置
func (w *WafVpConfigApi) GetIpWhitelistApi(c *gin.Context) {
	// 直接从全局变量获取IP白名单
	ipWhitelist := global.GWAF_IP_WHITELIST

	// 构造响应数据
	resp := response2.WafVpConfigIpWhitelistGetResp{
		IpWhitelist: ipWhitelist,
	}

	response.OkWithDetailed(resp, "获取IP白名单成功", c)
}
