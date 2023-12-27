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

type WafBlockUrlApi struct {
}

func (w *WafBlockUrlApi) AddApi(c *gin.Context) {
	var req request.WafBlockUrlAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafUrlBlockService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafUrlBlockService.AddApi(req)
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
func (w *WafBlockUrlApi) GetDetailApi(c *gin.Context) {
	var req request.WafBlockUrlDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafUrlBlockService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafBlockUrlApi) GetListApi(c *gin.Context) {
	var req request.WafBlockUrlSearchReq
	err := c.ShouldBind(&req)
	if err == nil {
		beans, total, _ := wafUrlBlockService.GetListApi(req)
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
func (w *WafBlockUrlApi) DelBlockUrlApi(c *gin.Context) {
	var req request.WafBlockUrlDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafUrlBlockService.GetDetailByIdApi(req.Id)
		err = wafUrlBlockService.DelApi(req)
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

func (w *WafBlockUrlApi) ModifyBlockUrlApi(c *gin.Context) {
	var req request.WafBlockUrlEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafUrlBlockService.ModifyApi(req)
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
func (w *WafBlockUrlApi) NotifyWaf(host_code string) {
	var urlWhites []model.URLBlockList
	global.GWAF_LOCAL_DB.Where("host_code = ? ", host_code).Find(&urlWhites)
	var chanInfo = spec.ChanCommonHost{
		HostCode: host_code,
		Type:     enums.ChanTypeBlockURL,
		Content:  urlWhites,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}
