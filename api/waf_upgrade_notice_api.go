package api

import (
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"

	"github.com/gin-gonic/gin"
)

type WafUpgradeNoticeApi struct {
}

// GetSummaryApi 升级须知汇总
// @Summary      升级须知汇总
// @Description  首页顶部提示条与登录弹窗用：本次从哪个版本升到哪个版本、还有几项待处理、是否需要弹窗、是否处于降级运行
// @Tags         升级须知
// @Produce      json
// @Param        lang  query     string  false  "语言(zh_CN/en_US)，默认中文"
// @Success      200   {object}  response.Response{data=response.UpgradeNoticeSummary}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /upgradenotice/summary [get]
func (w *WafUpgradeNoticeApi) GetSummaryApi(c *gin.Context) {
	var req request.WafUpgradeNoticeSummaryReq
	if err := c.ShouldBind(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	response.OkWithDetailed(wafUpgradeNoticeService.GetSummary(req.Lang), "获取成功", c)
}

// GetListApi 升级须知列表
// @Summary      升级须知列表
// @Description  分页查询本次升级带来的须知事项，可按状态/类型/引入版本过滤
// @Tags         升级须知
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafUpgradeNoticeSearchReq  true  "查询条件"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /upgradenotice/list [post]
func (w *WafUpgradeNoticeApi) GetListApi(c *gin.Context) {
	var req request.WafUpgradeNoticeSearchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	beans, total, err := wafUpgradeNoticeService.GetListApi(req)
	if err != nil {
		response.FailWithMessage("查询失败:"+err.Error(), c)
		return
	}
	response.OkWithDetailed(response.PageResult{
		List:      beans,
		Total:     total,
		PageIndex: req.PageIndex,
		PageSize:  req.PageSize,
	}, "获取成功", c)
}

// AckApi 标记为已处理
// @Summary      升级须知标记已处理
// @Description  用户点「我知道了」后调用
// @Tags         升级须知
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafUpgradeNoticeIdReq  true  "条目ID"
// @Success      200   {object}  response.Response  "操作成功"
// @Security     ApiKeyAuth
// @Router       /upgradenotice/ack [post]
func (w *WafUpgradeNoticeApi) AckApi(c *gin.Context) {
	w.setStatus(c, model.UpgradeNoticeStatusDone)
}

// IgnoreApi 忽略
// @Summary      升级须知忽略
// @Description  忽略后不再计入待处理，仍可在「全部」里查到
// @Tags         升级须知
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafUpgradeNoticeIdReq  true  "条目ID"
// @Success      200   {object}  response.Response  "操作成功"
// @Security     ApiKeyAuth
// @Router       /upgradenotice/ignore [post]
func (w *WafUpgradeNoticeApi) IgnoreApi(c *gin.Context) {
	w.setStatus(c, model.UpgradeNoticeStatusIgnored)
}

// RestoreApi 恢复为待处理
// @Summary      升级须知恢复待处理
// @Description  把已处理/已忽略的条目退回待处理
// @Tags         升级须知
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafUpgradeNoticeIdReq  true  "条目ID"
// @Success      200   {object}  response.Response  "操作成功"
// @Security     ApiKeyAuth
// @Router       /upgradenotice/restore [post]
func (w *WafUpgradeNoticeApi) RestoreApi(c *gin.Context) {
	w.setStatus(c, model.UpgradeNoticeStatusPending)
}

func (w *WafUpgradeNoticeApi) setStatus(c *gin.Context, status string) {
	var req request.WafUpgradeNoticeIdReq
	if err := c.ShouldBindJSON(&req); err != nil {
		response.FailWithMessage("解析失败", c)
		return
	}
	if err := wafUpgradeNoticeService.SetStatus(req.NoticeId, status, upgradeNoticeOperator(c)); err != nil {
		response.FailWithMessage("操作失败:"+err.Error(), c)
		return
	}
	response.OkWithMessage("操作成功", c)
}

// PopupShownApi 弹窗已展示回写
// @Summary      升级须知弹窗已展示
// @Description  登录弹窗关闭后调用，此后不再弹（一辈子只弹一次）
// @Tags         升级须知
// @Produce      json
// @Success      200  {object}  response.Response  "操作成功"
// @Security     ApiKeyAuth
// @Router       /upgradenotice/popupshown [post]
func (w *WafUpgradeNoticeApi) PopupShownApi(c *gin.Context) {
	if err := wafUpgradeNoticeService.MarkPopupShown(); err != nil {
		response.FailWithMessage("操作失败:"+err.Error(), c)
		return
	}
	response.OkWithMessage("操作成功", c)
}

// DowngradeAckApi 确认降级告警
// @Summary      确认降级告警
// @Description  用户点掉首页/列表页顶部的红色降级提示后调用；曾经运行过的最高版本再次变高时告警会重新出现
// @Tags         升级须知
// @Produce      json
// @Success      200  {object}  response.Response  "操作成功"
// @Security     ApiKeyAuth
// @Router       /upgradenotice/downgradeack [post]
func (w *WafUpgradeNoticeApi) DowngradeAckApi(c *gin.Context) {
	if err := wafUpgradeNoticeService.AckDowngrade(); err != nil {
		response.FailWithMessage("操作失败:"+err.Error(), c)
		return
	}
	response.OkWithMessage("操作成功", c)
}

// upgradeNoticeOperator 取当前登录账号，用于记录"谁处理的"
func upgradeNoticeOperator(c *gin.Context) string {
	if v, ok := c.Get("loginAccount"); ok {
		if account, ok := v.(string); ok {
			return account
		}
	}
	return ""
}
