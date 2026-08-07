package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

type WafHostConnApi struct {
}

// GetListApi 远程连接列表
// @Summary      远程连接列表
// @Description  当前连接到本机的所有TCP连接，SSH/RDP 端口会被标记
// @Tags         远程连接看板
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostConnSearchReq  true  "查询条件"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostconn/list [post]
func (w *WafHostConnApi) GetListApi(c *gin.Context) {
	var req request.WafHostConnSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	normalizeHostGuardPage(&req.PageIndex, &req.PageSize)

	list, total, summary, err := wafHostConnService.GetList(req)
	if err != nil {
		response.FailWithMessage("查询失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(gin.H{
		"list":      list,
		"total":     total,
		"pageIndex": req.PageIndex,
		"pageSize":  req.PageSize,
		"summary":   summary,
	}, "查询成功", c)
}

// GetSummaryApi 连接汇总
// @Summary      远程连接汇总
// @Tags         远程连接看板
// @Produce      json
// @Success      200  {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostconn/summary [get]
func (w *WafHostConnApi) GetSummaryApi(c *gin.Context) {
	summary, err := wafHostConnService.GetSummary()
	if err != nil {
		response.FailWithMessage("查询失败: "+err.Error(), c)
		return
	}
	response.OkWithDetailed(summary, "查询成功", c)
}

// RefreshApi 强制刷新快照
// @Summary      强制刷新连接快照
// @Description  丢弃缓存立即重新采集（页面上的手工刷新按钮）
// @Tags         远程连接看板
// @Produce      json
// @Success      200  {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostconn/refresh [get]
func (w *WafHostConnApi) RefreshApi(c *gin.Context) {
	wafHostConnService.InvalidateSnapshot()
	response.OkWithMessage("已刷新", c)
}

// BlockApi 从连接看板一键封禁
// @Summary      封禁某个连接来源IP
// @Description  转调主机防爆破的手工封禁，走同一套账本与解封流程
// @Tags         远程连接看板
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafHostGuardManualBanReq  true  "封禁参数"
// @Success      200   {object}  response.Response
// @Security     ApiKeyAuth
// @Router       /hostconn/block [post]
func (w *WafHostConnApi) BlockApi(c *gin.Context) {
	var req request.WafHostGuardManualBanReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}
	if err := checkBanTargetIP(req.IP); err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	if req.BanMinutes < 0 {
		response.FailWithMessage("封禁时长不能为负数（0 表示永久封禁）", c)
		return
	}
	if req.Reason == "" {
		req.Reason = "管理员从远程连接看板手工封禁"
	}
	if err := wafHostGuardService.ManualBan(req); err != nil {
		response.FailWithMessage("封禁失败: "+err.Error(), c)
		return
	}
	// 封完立刻让下一次查询看到最新状态
	wafHostConnService.InvalidateSnapshot()
	response.OkWithMessage("已封禁", c)
}
