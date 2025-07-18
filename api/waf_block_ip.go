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

type WafBlockIpApi struct {
}

func (w *WafBlockIpApi) AddApi(c *gin.Context) {
	var req request.WafBlockIpAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafIpBlockService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafIpBlockService.AddApi(req)
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
func (w *WafBlockIpApi) GetDetailApi(c *gin.Context) {
	var req request.WafBlockIpDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafIpBlockService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafBlockIpApi) GetListApi(c *gin.Context) {
	var req request.WafBlockIpSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		wafIpWhites, total, _ := wafIpBlockService.GetListApi(req)
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
func (w *WafBlockIpApi) DelBlockIpApi(c *gin.Context) {
	var req request.WafBlockIpDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafIpBlockService.GetDetailByIdApi(req.Id)
		err = wafIpBlockService.DelApi(req)
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

func (w *WafBlockIpApi) ModifyBlockIpApi(c *gin.Context) {
	var req request.WafBlockIpEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafIpBlockService.ModifyApi(req)
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

// BatchDelBlockIpApi 批量删除IP黑名单
func (w *WafBlockIpApi) BatchDelBlockIpApi(c *gin.Context) {
	var req request.WafBlockIpBatchDelReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafIpBlockService.GetHostCodesByIds(req.Ids)
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		// 执行批量删除
		err = wafIpBlockService.BatchDelApi(req)
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

// DelAllBlockIpApi 删除指定网站的所有IP黑名单
func (w *WafBlockIpApi) DelAllBlockIpApi(c *gin.Context) {
	var req request.WafBlockIpDelAllReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafIpBlockService.GetHostCodes()
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		err = wafIpBlockService.DelAllApi(req)
		if err != nil {
			response.FailWithMessage("全量删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			response.OkWithMessage("成功删除该网站的所有IP黑名单", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

/*
*
通知到waf引擎实时生效
*/
func (w *WafBlockIpApi) NotifyWaf(host_code string) {
	var ipWhites []model.IPBlockList
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Find(&ipWhites)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeBlockIP,
		Content:  ipWhites,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}
