package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/service/waf_service"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafNotifyChannelApi struct{}

var wafNotifyChannelService = waf_service.WafNotifyChannelServiceApp

// AddApi 新增通知渠道
// @Summary      新增通知渠道
// @Description  新增一个通知渠道（支持企业微信、钉钉、Server酱等）
// @Tags         通知-渠道
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafNotifyChannelAddReq  true  "通知渠道配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /notify/channel/add [post]
func (w *WafNotifyChannelApi) AddApi(c *gin.Context) {
	var req request.WafNotifyChannelAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafNotifyChannelService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafNotifyChannelService.AddApi(req)
			if err == nil {
				response.OkWithMessage("添加成功", c)
			} else {
				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前通知渠道已经存在", c)
			return
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetDetailApi 获取通知渠道详情
// @Summary      获取通知渠道详情
// @Description  根据ID获取通知渠道详情
// @Tags         通知-渠道
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "渠道ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /notify/channel/detail [get]
func (w *WafNotifyChannelApi) GetDetailApi(c *gin.Context) {
	var req request.WafNotifyChannelDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafNotifyChannelService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取通知渠道列表
// @Summary      获取通知渠道列表
// @Description  分页查询通知渠道列表
// @Tags         通知-渠道
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafNotifyChannelSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /notify/channel/list [post]
func (w *WafNotifyChannelApi) GetListApi(c *gin.Context) {
	var req request.WafNotifyChannelSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafNotifyChannelService.GetListApi(req)
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

// DelApi 删除通知渠道
// @Summary      删除通知渠道
// @Description  根据ID删除通知渠道
// @Tags         通知-渠道
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "渠道ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /notify/channel/del [get]
func (w *WafNotifyChannelApi) DelApi(c *gin.Context) {
	var req request.WafNotifyChannelDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafNotifyChannelService.DelApi(req)
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

// ModifyApi 编辑通知渠道
// @Summary      编辑通知渠道
// @Description  修改通知渠道配置
// @Tags         通知-渠道
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafNotifyChannelEditReq  true  "通知渠道配置"
// @Success      200   {object}  response.Response  "编辑成功"
// @Security     ApiKeyAuth
// @Router       /notify/channel/edit [post]
func (w *WafNotifyChannelApi) ModifyApi(c *gin.Context) {
	var req request.WafNotifyChannelEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafNotifyChannelService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// TestApi 测试通知渠道
func (w *WafNotifyChannelApi) TestApi(c *gin.Context) {
	var req request.WafNotifyChannelTestReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafNotifyChannelService.TestChannelApi(req)
		if err != nil {
			response.FailWithMessage("测试失败: "+err.Error(), c)
		} else {
			response.OkWithMessage("测试成功，请检查是否收到通知", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
