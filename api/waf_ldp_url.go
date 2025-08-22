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

type WafLdpUrlApi struct {
}

func (w *WafLdpUrlApi) AddApi(c *gin.Context) {
	var req request.WafLdpUrlAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafLdpUrlService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafLdpUrlService.AddApi(req)
			if err == nil {

				response.OkWithMessage("添加成功", c)
			} else {
				w.NotifyWaf(req.HostCode)
				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前网站的Url已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafLdpUrlApi) GetDetailApi(c *gin.Context) {
	var req request.WafLdpUrlDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafLdpUrlService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafLdpUrlApi) GetListApi(c *gin.Context) {
	var req request.WafLdpUrlSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafLdpUrlService.GetListApi(req)
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
func (w *WafLdpUrlApi) DelLdpUrlApi(c *gin.Context) {
	var req request.WafLdpUrlDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafLdpUrlService.GetDetailByIdApi(req.Id)
		err = wafLdpUrlService.DelApi(req)
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

func (w *WafLdpUrlApi) ModifyLdpUrlApi(c *gin.Context) {
	var req request.WafLdpUrlEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafLdpUrlService.ModifyApi(req)
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
func (w *WafLdpUrlApi) NotifyWaf(host_code string) {
	var idpUrls []model.LDPUrl
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Find(&idpUrls)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeLdp,
		Content:  idpUrls,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}

// BatchDelLdpUrlApi 批量删除隐私保护URL
func (w *WafLdpUrlApi) BatchDelLdpUrlApi(c *gin.Context) {
	var req request.WafLdpUrlBatchDelReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafLdpUrlService.GetHostCodesByIds(req.Ids)
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		// 执行批量删除
		err = wafLdpUrlService.BatchDelApi(req)
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

// DelAllLdpUrlApi 删除指定网站的所有隐私保护URL
func (w *WafLdpUrlApi) DelAllLdpUrlApi(c *gin.Context) {
	var req request.WafLdpUrlDelAllReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafLdpUrlService.GetHostCodes()
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		err = wafLdpUrlService.DelAllApi(req)
		if err != nil {
			response.FailWithMessage("全部删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			if len(req.HostCode) > 0 {
				response.OkWithMessage("成功删除该网站的所有隐私保护URL", c)
			} else {
				response.OkWithMessage("成功删除所有隐私保护URL", c)
			}
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
