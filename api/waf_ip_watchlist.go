package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

// AddIPWatchlistApi 加入重点 IP 观察名单（或续期）
func (w *WafLogAPi) AddIPWatchlistApi(c *gin.Context) {
	var req request.WafIPWatchlistAddReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数错误: "+err.Error(), c)
		return
	}
	if err := wafIPWatchlistService.AddApi(req); err != nil {
		response.FailWithMessage("加入观察名单失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("已加入观察名单", c)
}

// DelIPWatchlistApi 移出观察名单
func (w *WafLogAPi) DelIPWatchlistApi(c *gin.Context) {
	var req request.WafIPWatchlistDelReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数错误: "+err.Error(), c)
		return
	}
	if err := wafIPWatchlistService.DelApi(req.IP); err != nil {
		response.FailWithMessage("移除失败: "+err.Error(), c)
		return
	}
	response.OkWithMessage("已移出观察名单", c)
}

// GetIPWatchlistApi 观察名单分页
func (w *WafLogAPi) GetIPWatchlistApi(c *gin.Context) {
	var req request.WafIPWatchlistSearch
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("参数错误: "+err.Error(), c)
		return
	}
	list, total, err := wafIPWatchlistService.ListApi(req)
	if err != nil {
		response.FailWithMessage("查询失败: "+err.Error(), c)
		return
	}
	response.OkWithData(response.PageResult{
		List:     list,
		Total:    total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, c)
}
