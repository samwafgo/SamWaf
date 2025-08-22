package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafAllowIpApi struct {
}

func (w *WafAllowIpApi) AddApi(c *gin.Context) {
	var req request.WafAllowIpAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafIpAllowService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafIpAllowService.AddApi(req)
			if err == nil {
				w.NotifyWaf(req.HostCode)
				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前网站的IP已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafAllowIpApi) GetDetailApi(c *gin.Context) {
	var req request.WafAllowIpDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafIpAllowService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafAllowIpApi) GetListApi(c *gin.Context) {
	var req request.WafAllowIpSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		wafIpWhites, total, _ := wafIpAllowService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      wafIpWhites,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafAllowIpApi) DelAllowIpApi(c *gin.Context) {
	var req request.WafAllowIpDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafIpAllowService.GetDetailByIdApi(req.Id)
		err = wafIpAllowService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			w.NotifyWaf(bean.HostCode)
			response.OkWithMessage("删除成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafAllowIpApi) ModifyAllowIpApi(c *gin.Context) {
	var req request.WafAllowIpEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafIpAllowService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			w.NotifyWaf(req.HostCode)
			response.OkWithMessage("编辑成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

/*
*
通知到waf引擎实时生效
*/
func (w *WafAllowIpApi) NotifyWaf(host_code string) {
	var ipWhites []model.IPAllowList
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Find(&ipWhites)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeAllowIP,
		Content:  ipWhites,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}

// BatchDelAllowIpApi 批量删除IP白名单
func (w *WafAllowIpApi) BatchDelAllowIpApi(c *gin.Context) {
	var req request.WafAllowIpBatchDelReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafIpAllowService.GetHostCodesByIds(req.Ids)
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		// 执行批量删除
		err = wafIpAllowService.BatchDelApi(req)
		if err != nil {
			response.FailWithMessage("批量删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			response.OkWithMessage(fmt.Sprintf("成功删除 %d 条记录", len(req.Ids)), c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelAllAllowIpApi 删除指定网站的所有IP白名单
func (w *WafAllowIpApi) DelAllAllowIpApi(c *gin.Context) {
	var req request.WafAllowIpDelAllReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafIpAllowService.GetHostCodes()
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		err = wafIpAllowService.DelAllApi(req)
		if err != nil {
			response.FailWithMessage("全量删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			if len(req.HostCode) > 0 {
				response.OkWithMessage("成功删除该网站的所有IP白名单", c)
			} else {
				response.OkWithMessage("成功删除所有IP白名单", c)
			}
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
