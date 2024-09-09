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
