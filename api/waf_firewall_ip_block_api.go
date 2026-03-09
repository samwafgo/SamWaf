package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafFirewallIPBlockApi struct {
}

// AddApi 新增防火墙IP封禁
// @Summary      新增防火墙IP封禁
// @Description  新增一条防火墙IP封禁规则（系统级别封禁，所有端口生效）
// @Tags         防火墙-IP封禁
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafFirewallIPBlockAddReq  true  "IP封禁配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /firewallipblock/add [post]
func (w *WafFirewallIPBlockApi) AddApi(c *gin.Context) {
	var req request.WafFirewallIPBlockAddReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败: "+err.Error(), c)
		return
	}

	err = wafFirewallIPBlockService.AddApi(req)
	if err != nil {
		response.FailWithMessage("添加失败: "+err.Error(), c)
		return
	}

	response.OkWithMessage("添加成功，IP已在系统防火墙层面封禁", c)
}

// GetDetailApi 获取防火墙IP封禁详情
func (w *WafFirewallIPBlockApi) GetDetailApi(c *gin.Context) {
	var req request.WafFirewallIPBlockDetailReq
	err := c.ShouldBind(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	bean := wafFirewallIPBlockService.GetDetailApi(req)
	response.OkWithDetailed(bean, "获取成功", c)
}

// GetListApi 获取防火墙IP封禁列表
// @Summary      获取防火墙IP封禁列表
// @Description  分页查询防火墙IP封禁规则列表
// @Tags         防火墙-IP封禁
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafFirewallIPBlockSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /firewallipblock/list [post]
func (w *WafFirewallIPBlockApi) GetListApi(c *gin.Context) {
	var req request.WafFirewallIPBlockSearchReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	list, total, err := wafFirewallIPBlockService.GetListApi(req)
	if err != nil {
		response.FailWithMessage("获取失败: "+err.Error(), c)
		return
	}

	response.OkWithDetailed(response.PageResult{
		List:      list,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}

// DelApi 删除防火墙IP封禁
// @Summary      删除防火墙IP封禁
// @Description  根据ID删除防火墙IP封禁规则，同步从系统防火墙解除封禁
// @Tags         防火墙-IP封禁
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "封禁记录ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /firewallipblock/del [get]
func (w *WafFirewallIPBlockApi) DelApi(c *gin.Context) {
	var req request.WafFirewallIPBlockDelReq
	err := c.ShouldBind(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	err = wafFirewallIPBlockService.DelApi(req)
	if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
		response.FailWithMessage("请检测参数", c)
	} else if err != nil {
		response.FailWithMessage("删除失败: "+err.Error(), c)
	} else {
		response.OkWithMessage("删除成功，IP已从系统防火墙解除封禁", c)
	}
}

// ModifyApi 编辑防火墙IP封禁
// @Summary      编辑防火墙IP封禁
// @Description  修改防火墙IP封禁规则
// @Tags         防火墙-IP封禁
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafFirewallIPBlockEditReq  true  "IP封禁配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /firewallipblock/edit [post]
func (w *WafFirewallIPBlockApi) ModifyApi(c *gin.Context) {
	var req request.WafFirewallIPBlockEditReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	err = wafFirewallIPBlockService.ModifyApi(req)
	if err != nil {
		response.FailWithMessage("编辑失败: "+err.Error(), c)
	} else {
		response.OkWithMessage("编辑成功", c)
	}
}

// BatchDelApi 批量删除防火墙IP封禁
func (w *WafFirewallIPBlockApi) BatchDelApi(c *gin.Context) {
	var req request.WafFirewallIPBlockBatchDelReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	err = wafFirewallIPBlockService.BatchDelApi(req)
	if err != nil {
		response.FailWithMessage("批量删除失败: "+err.Error(), c)
	} else {
		response.OkWithMessage(fmt.Sprintf("成功删除 %d 条记录", len(req.Ids)), c)
	}
}

// BatchAddApi 批量添加防火墙IP封禁
func (w *WafFirewallIPBlockApi) BatchAddApi(c *gin.Context) {
	var req request.WafFirewallIPBlockBatchAddReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	successCount, failedIPs, err := wafFirewallIPBlockService.BatchAddApi(req)
	if err != nil {
		msg := fmt.Sprintf("批量添加完成，成功 %d 个，失败 %d 个", successCount, len(failedIPs))
		if len(failedIPs) > 0 {
			msg += fmt.Sprintf("，失败的IP: %v", failedIPs)
		}
		response.FailWithMessage(msg, c)
	} else {
		response.OkWithMessage(fmt.Sprintf("批量添加成功，共封禁 %d 个IP", successCount), c)
	}
}

// EnableApi 启用防火墙IP封禁
func (w *WafFirewallIPBlockApi) EnableApi(c *gin.Context) {
	var req request.WafFirewallIPBlockEnableReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	err = wafFirewallIPBlockService.EnableApi(req)
	if err != nil {
		response.FailWithMessage("启用失败: "+err.Error(), c)
	} else {
		response.OkWithMessage("启用成功，IP已在系统防火墙层面封禁", c)
	}
}

// DisableApi 禁用防火墙IP封禁
func (w *WafFirewallIPBlockApi) DisableApi(c *gin.Context) {
	var req request.WafFirewallIPBlockDisableReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	err = wafFirewallIPBlockService.DisableApi(req)
	if err != nil {
		response.FailWithMessage("禁用失败: "+err.Error(), c)
	} else {
		response.OkWithMessage("禁用成功，IP已从系统防火墙解除封禁", c)
	}
}

// SyncApi 同步防火墙规则（从数据库恢复到系统防火墙）
func (w *WafFirewallIPBlockApi) SyncApi(c *gin.Context) {
	var req request.WafFirewallIPBlockSyncReq
	err := c.ShouldBindJSON(&req)
	if err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}

	successCount, failedCount, err := wafFirewallIPBlockService.SyncFirewallRules(req.HostCode)
	if err != nil {
		response.FailWithMessage("同步失败: "+err.Error(), c)
	} else {
		msg := fmt.Sprintf("同步完成，成功 %d 个", successCount)
		if failedCount > 0 {
			msg += fmt.Sprintf("，失败 %d 个", failedCount)
		}
		response.OkWithMessage(msg, c)
	}
}

// ClearExpiredApi 清理过期的封禁规则
func (w *WafFirewallIPBlockApi) ClearExpiredApi(c *gin.Context) {
	count, err := wafFirewallIPBlockService.ClearExpiredRules()
	if err != nil {
		response.FailWithMessage("清理失败: "+err.Error(), c)
	} else {
		response.OkWithMessage(fmt.Sprintf("成功清理 %d 条过期规则", count), c)
	}
}

// GetStatisticsApi 获取统计信息
func (w *WafFirewallIPBlockApi) GetStatisticsApi(c *gin.Context) {
	stats := wafFirewallIPBlockService.GetStatistics()
	response.OkWithDetailed(stats, "获取成功", c)
}
