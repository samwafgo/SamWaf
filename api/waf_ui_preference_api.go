package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

type WafUIPreferenceApi struct {
}

// GetApi 获取当前登录账号的界面偏好
func (w *WafUIPreferenceApi) GetApi(c *gin.Context) {
	var req request.WafUIPreferenceGetReq
	if err := c.ShouldBindQuery(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	// 登录账号由 auth 中间件写入；OpenApi Key 方式访问时不会写入，需拦住
	account := c.GetString("loginAccount")
	if account == "" {
		response.FailWithMessage("登录信息异常", c)
		return
	}
	bean, err := wafUIPreferenceService.GetApi(account, req.PrefName)
	if err != nil {
		response.FailWithMessage("获取失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(bean, "获取成功", c)
}

// SaveApi 保存当前登录账号的界面偏好
func (w *WafUIPreferenceApi) SaveApi(c *gin.Context) {
	var req request.WafUIPreferenceSaveReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	account := c.GetString("loginAccount")
	if account == "" {
		response.FailWithMessage("登录信息异常", c)
		return
	}
	if err := wafUIPreferenceService.SaveApi(account, req); err != nil {
		response.FailWithMessage("保存失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("保存成功", c)
}
