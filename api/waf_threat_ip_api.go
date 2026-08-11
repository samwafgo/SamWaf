package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

type WafThreatIPApi struct {
}

// AddApi 新增威胁情报订阅渠道
func (w *WafThreatIPApi) AddApi(c *gin.Context) {
	var req request.WafThreatIPChannelAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if err := wafThreatIPService.AddApi(req); err != nil {
		response.FailWithMessage("添加失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("添加成功", c)
}

// ModifyApi 修改威胁情报订阅渠道
func (w *WafThreatIPApi) ModifyApi(c *gin.Context) {
	var req request.WafThreatIPChannelEditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if err := wafThreatIPService.ModifyApi(req); err != nil {
		response.FailWithMessage("修改失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("修改已保存，正在后台生效(启用会回灌防火墙、停用会移除)，完成后通知中心会提示", c)
}

// DelApi 删除威胁情报订阅渠道
func (w *WafThreatIPApi) DelApi(c *gin.Context) {
	var req request.WafThreatIPChannelDelReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafThreatIPService.DelApi(req.Id); err != nil {
		response.FailWithMessage("删除失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("删除成功，正在后台清理防火墙落地，完成后通知中心会提示", c)
}

// GetListApi 分页获取渠道列表
func (w *WafThreatIPApi) GetListApi(c *gin.Context) {
	var req request.WafThreatIPChannelSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	list, total, err := wafThreatIPService.GetListApi(req)
	if err != nil {
		response.FailWithMessage("查询失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}

// GetDetailApi 获取渠道详情
func (w *WafThreatIPApi) GetDetailApi(c *gin.Context) {
	var req request.WafThreatIPChannelDetailReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	bean := wafThreatIPService.GetDetailByIdApi(req.Id)
	response.OkWithDetailed(bean, "获取成功", c)
}

// SyncApi 手动触发某渠道立即同步
func (w *WafThreatIPApi) SyncApi(c *gin.Context) {
	var req request.WafThreatIPChannelSyncReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if err := wafThreatIPService.SyncByIdApi(req.Id); err != nil {
		response.FailWithMessage("同步失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("同步任务已开始(后台拉取，大列表需数秒~数十秒)，完成后通知中心会提示，可刷新列表查看状态", c)
}

// LandedSummaryApi 订阅落地汇总(供防火墙IP封禁页/IP黑名单页"订阅来源"Tab)
func (w *WafThreatIPApi) LandedSummaryApi(c *gin.Context) {
	var req request.WafThreatIPLandedSummaryReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	list := wafThreatIPService.GetLandedSummary(req.Land)
	response.OkWithDetailed(list, "获取成功", c)
}

// LandedIPsApi 某渠道落地 IP 分页浏览(只读)
func (w *WafThreatIPApi) LandedIPsApi(c *gin.Context) {
	var req request.WafThreatIPLandedIPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	ips, total := wafThreatIPService.GetLandedIPs(req.Code, req.Keyword, req.OnlyExcluded == 1, req.PageIndex, req.PageSize)
	response.OkWithDetailed(response.PageResult{
		List:      ips,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}
