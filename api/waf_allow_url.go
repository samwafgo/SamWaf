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

type WafAllowUrlApi struct {
}

func (w *WafAllowUrlApi) AddApi(c *gin.Context) {
	var req request.WafAllowUrlAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafUrlAllowService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafUrlAllowService.AddApi(req)
			if err == nil {
				w.NotifyWaf(req.HostCode)
				response.OkWithMessage("添加成功", c)
			} else {

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
func (w *WafAllowUrlApi) GetDetailApi(c *gin.Context) {
	var req request.WafAllowUrlDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafUrlAllowService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafAllowUrlApi) GetListApi(c *gin.Context) {
	var req request.WafAllowUrlSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafUrlAllowService.GetListApi(req)
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
func (w *WafAllowUrlApi) DelAllowUrlApi(c *gin.Context) {
	var req request.WafAllowUrlDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafUrlAllowService.GetDetailByIdApi(req.Id)
		err = wafUrlAllowService.DelApi(req)
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

func (w *WafAllowUrlApi) ModifyAllowUrlApi(c *gin.Context) {
	var req request.WafAllowUrlEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafUrlAllowService.ModifyApi(req)
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
func (w *WafAllowUrlApi) NotifyWaf(host_code string) {
	var urlWhites []model.URLAllowList
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Find(&urlWhites)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeAllowURL,
		Content:  urlWhites,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}

// 新增批量删除API
func (w *WafAllowUrlApi) BatchDelAllowUrlApi(c *gin.Context) {
	var req request.WafAllowUrlBatchDelReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafUrlAllowService.GetHostCodesByIds(req.Ids)
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		// 执行批量删除
		err = wafUrlAllowService.BatchDelApi(req)
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

// 新增全部删除API
func (w *WafAllowUrlApi) DelAllAllowUrlApi(c *gin.Context) {
	var req request.WafAllowUrlDelAllReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 先获取要删除的记录对应的HostCode，用于后续通知WAF引擎
		hostCodes, err := wafUrlAllowService.GetHostCodes()
		if err != nil {
			response.FailWithMessage("获取网站信息失败", c)
			return
		}

		err = wafUrlAllowService.DelAllApi(req)
		if err != nil {
			response.FailWithMessage("全部删除失败: "+err.Error(), c)
		} else {
			// 通知所有相关的网站更新配置
			for _, hostCode := range hostCodes {
				w.NotifyWaf(hostCode)
			}
			if len(req.HostCode) > 0 {
				response.OkWithMessage("成功删除该网站的所有URL白名单", c)
			} else {
				response.OkWithMessage("成功删除所有URL白名单", c)
			}
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
