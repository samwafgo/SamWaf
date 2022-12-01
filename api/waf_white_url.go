package api

import (
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafWhiteUrlApi struct {
}

func (w *WafWhiteUrlApi) AddApi(c *gin.Context) {
	var req request.WafWhiteUrlAddReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafUrlWhiteService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafUrlWhiteService.AddApi(req)
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
func (w *WafWhiteUrlApi) GetDetailApi(c *gin.Context) {
	var req request.WafWhiteUrlDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafUrlWhiteService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafWhiteUrlApi) GetListApi(c *gin.Context) {
	var req request.WafWhiteUrlSearchReq
	err := c.ShouldBind(&req)
	if err == nil {
		beans, total, _ := wafUrlWhiteService.GetListApi(req)
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
func (w *WafWhiteUrlApi) DelWhiteUrlApi(c *gin.Context) {
	var req request.WafWhiteUrlDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafUrlWhiteService.GetDetailByIdApi(req.Id)
		err = wafUrlWhiteService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			w.NotifyWaf(bean.HostCode)
			response.FailWithMessage("删除成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafWhiteUrlApi) ModifyWhiteUrlApi(c *gin.Context) {
	var req request.WafWhiteUrlEditReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafUrlWhiteService.ModifyApi(req)
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
func (w *WafWhiteUrlApi) NotifyWaf(host_code string) {
	var urlWhites []model.URLWhiteList
	global.GWAF_LOCAL_DB.Debug().Where("host_code = ? ", host_code).Find(&urlWhites)
	global.GWAF_CHAN_UrlWhite <- urlWhites
}
