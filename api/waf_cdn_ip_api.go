package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

// WafCDNIPApi CDN 厂商回源段中心库管理接口。
// 读接口(列表/详情/浏览)任意管理员可看；写接口(开关自拉/设凭证/立即拉取)限系统管理员(路由层控制)。
type WafCDNIPApi struct {
}

// GetListApi 厂商列表(合并元数据+运行态，脱敏，不含明文凭证)
func (w *WafCDNIPApi) GetListApi(c *gin.Context) {
	list := wafCDNIPService.GetProviderList()
	response.OkWithDetailed(list, "获取成功", c)
}

// GetInfoApi 单厂商详情(供 host 表单/管理端只读展示)
func (w *WafCDNIPApi) GetInfoApi(c *gin.Context) {
	provider := c.Query("provider")
	if provider == "" {
		response.FailWithMessage("缺少 provider 参数", c)
		return
	}
	info := wafCDNIPService.GetProviderInfo(provider)
	if info == nil {
		response.FailWithMessage("未知 CDN 厂商", c)
		return
	}
	response.OkWithDetailed(info, "获取成功", c)
}

// RangesApi 分页浏览某厂商回源段(只读)
func (w *WafCDNIPApi) RangesApi(c *gin.Context) {
	var req request.WafCDNProviderRangesReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	ips, total := wafCDNIPService.GetProviderRanges(req.Provider, req.Keyword, req.PageIndex, req.PageSize)
	response.OkWithDetailed(response.PageResult{
		List:      ips,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}

// SetAutoFetchApi 开/关某厂商自动拉取(开启会立即触发一次)
func (w *WafCDNIPApi) SetAutoFetchApi(c *gin.Context) {
	var req request.WafCDNProviderAutoFetchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if err := wafCDNIPService.SetAutoFetch(req.Provider, req.AutoFetch, req.IntervalHour); err != nil {
		response.FailWithMessage("设置失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("设置成功", c)
}

// SetCredentialApi 保存认证型厂商凭证(加密落库，绝不回显)
func (w *WafCDNIPApi) SetCredentialApi(c *gin.Context) {
	var req request.WafCDNProviderCredentialReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if err := wafCDNIPService.SetCredential(req.Provider, req.SecretId, req.SecretKey, req.ExtraParam); err != nil {
		response.FailWithMessage("保存失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("保存成功", c)
}

// ClearCredentialApi 清空某厂商凭证
func (w *WafCDNIPApi) ClearCredentialApi(c *gin.Context) {
	var req request.WafCDNProviderRefreshReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if err := wafCDNIPService.ClearCredential(req.Provider); err != nil {
		response.FailWithMessage("清空失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("清空成功", c)
}

// RefreshApi 立即拉取某厂商回源段一次
func (w *WafCDNIPApi) RefreshApi(c *gin.Context) {
	var req request.WafCDNProviderRefreshReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if err := wafCDNIPService.RefreshProvider(req.Provider); err != nil {
		response.FailWithMessage("拉取失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("拉取成功", c)
}
