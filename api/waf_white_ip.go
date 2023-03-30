package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafWhiteIpApi struct {
}

func (w *WafWhiteIpApi) AddApi(c *gin.Context) {
	var req request.WafWhiteIpAddReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafIpWhiteService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafIpWhiteService.AddApi(req)
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
func (w *WafWhiteIpApi) GetDetailApi(c *gin.Context) {
	var req request.WafWhiteIpDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafIpWhiteService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafWhiteIpApi) GetListApi(c *gin.Context) {
	var req request.WafWhiteIpSearchReq
	err := c.ShouldBind(&req)
	if err == nil {
		wafIpWhites, total, _ := wafIpWhiteService.GetListApi(req)
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
func (w *WafWhiteIpApi) DelWhiteIpApi(c *gin.Context) {
	var req request.WafWhiteIpDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafIpWhiteService.GetDetailByIdApi(req.Id)
		err = wafIpWhiteService.DelApi(req)
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

func (w *WafWhiteIpApi) ModifyWhiteIpApi(c *gin.Context) {
	var req request.WafWhiteIpEditReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafIpWhiteService.ModifyApi(req)
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
func (w *WafWhiteIpApi) NotifyWaf(host_code string) {
	var ipWhites []model.IPWhiteList
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Find(&ipWhites)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeWhiteIP,
		Content:  ipWhites,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}
