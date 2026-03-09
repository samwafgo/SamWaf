package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafNotifySubscriptionApi struct{}

var wafNotifySubscriptionService = waf_service.WafNotifySubscriptionServiceApp

// AddApi 新增通知订阅
// @Summary      新增通知订阅
// @Description  新增一条通知订阅，将事件类型与渠道关联
// @Tags         通知-订阅
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafNotifySubscriptionAddReq  true  "通知订阅配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /notify/subscription/add [post]
func (w *WafNotifySubscriptionApi) AddApi(c *gin.Context) {
	var req request.WafNotifySubscriptionAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafNotifySubscriptionService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafNotifySubscriptionService.AddApi(req)
			if err == nil {
				response.OkWithMessage("添加成功", c)
			} else {
				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("该渠道已订阅此消息类型", c)
			return
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetDetailApi 获取通知订阅详情
func (w *WafNotifySubscriptionApi) GetDetailApi(c *gin.Context) {
	var req request.WafNotifySubscriptionDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafNotifySubscriptionService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取通知订阅列表
// @Summary      获取通知订阅列表
// @Description  分页查询通知订阅列表
// @Tags         通知-订阅
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafNotifySubscriptionSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /notify/subscription/list [post]
func (w *WafNotifySubscriptionApi) GetListApi(c *gin.Context) {
	var req request.WafNotifySubscriptionSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafNotifySubscriptionService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      beans,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelApi 删除通知订阅
// @Summary      删除通知订阅
// @Description  根据ID删除通知订阅
// @Tags         通知-订阅
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "订阅ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /notify/subscription/del [get]
func (w *WafNotifySubscriptionApi) DelApi(c *gin.Context) {
	var req request.WafNotifySubscriptionDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafNotifySubscriptionService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			response.OkWithMessage("删除成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ModifyApi 修改通知订阅
func (w *WafNotifySubscriptionApi) ModifyApi(c *gin.Context) {
	var req request.WafNotifySubscriptionEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafNotifySubscriptionService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
