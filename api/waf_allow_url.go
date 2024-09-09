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
