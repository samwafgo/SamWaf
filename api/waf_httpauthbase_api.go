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

type WafHttpAuthBaseApi struct {
}

func (w *WafHttpAuthBaseApi) AddApi(c *gin.Context) {
	var req request.WafHttpAuthBaseAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {

		cnt := wafHttpAuthBaseService.CheckIsExistApi(req)
		if cnt == 0 {
			err = wafHttpAuthBaseService.AddApi(req)
			if err == nil {
				w.NotifyWaf(req.HostCode)
				response.OkWithMessage("添加成功", c)
			} else {
				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前记录已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafHttpAuthBaseApi) GetDetailApi(c *gin.Context) {
	var req request.WafHttpAuthBaseDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafHttpAuthBaseService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafHttpAuthBaseApi) GetListApi(c *gin.Context) {
	var req request.WafHttpAuthBaseSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		HttpAuthBase, total, _ := wafHttpAuthBaseService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      HttpAuthBase,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafHttpAuthBaseApi) DelApi(c *gin.Context) {
	var req request.WafHttpAuthBaseDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafHttpAuthBaseService.GetDetailByIdApi(req.Id)
		err = wafHttpAuthBaseService.DelApi(req)
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

func (w *WafHttpAuthBaseApi) ModifyApi(c *gin.Context) {
	var req request.WafHttpAuthBaseEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafHttpAuthBaseService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误"+err.Error(), c)
		} else {
			w.NotifyWaf(req.HostCode)
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// NotifyWaf  通知到waf引擎实时生效
func (w *WafHttpAuthBaseApi) NotifyWaf(hostCode string) {
	var list []model.HttpAuthBase
	global.GWAF_LOCAL_DB.Where("host_code = ? ", hostCode).Find(&list)
	var chanInfo = spec.ChanCommonHost{
		HostCode: hostCode,
		Type:     enums.ChanTypeHttpauth,
		Content:  list,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}
