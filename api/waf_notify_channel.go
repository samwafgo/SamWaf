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

// AddApi 添加通知渠道
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

// ModifyApi 修改通知渠道
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
