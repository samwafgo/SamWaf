package api

import (
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/model/spec"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafLoadBalanceApi struct {
}

func (w *WafLoadBalanceApi) AddApi(c *gin.Context) {
	var req request.WafLoadBalanceAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafLoadBalanceService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafLoadBalanceService.AddApi(req)
			if err == nil {
				w.NotifyWaf(req.HostCode)
				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前负载IP+端口已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafLoadBalanceApi) GetDetailApi(c *gin.Context) {
	var req request.WafLoadBalanceDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafLoadBalanceService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafLoadBalanceApi) GetListApi(c *gin.Context) {
	var req request.WafLoadBalanceSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		list, total, _ := wafLoadBalanceService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      list,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafLoadBalanceApi) DelLoadBalanceApi(c *gin.Context) {
	var req request.WafLoadBalanceDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafLoadBalanceService.GetDetailByIdApi(req.Id)
		err = wafLoadBalanceService.DelApi(req)
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

func (w *WafLoadBalanceApi) ModifyApi(c *gin.Context) {
	var req request.WafLoadBalanceEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafLoadBalanceService.ModifyApi(req)
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
func (w *WafLoadBalanceApi) NotifyWaf(host_code string) {

	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeLoadBalance,
		Content:  nil,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}
