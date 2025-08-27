package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafCaServerInfoApi struct {
}

func (w *WafCaServerInfoApi) AddApi(c *gin.Context) {
	var req request.WafCaServerInfoAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {

		cnt := wafCaServerInfoService.CheckIsExistApi(req)
		if cnt == 0 {
			err = wafCaServerInfoService.AddApi(req)
			if err == nil {
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

func (w *WafCaServerInfoApi) GetDetailApi(c *gin.Context) {
	var req request.WafCaServerInfoDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafCaServerInfoService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafCaServerInfoApi) GetListApi(c *gin.Context) {
	var req request.WafCaServerInfoSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		CaServerInfo, total, _ := wafCaServerInfoService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      CaServerInfo,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafCaServerInfoApi) DelApi(c *gin.Context) {
	var req request.WafCaServerInfoDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafCaServerInfoService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			response.OkWithMessage("删除成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafCaServerInfoApi) ModifyApi(c *gin.Context) {
	var req request.WafCaServerInfoEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafCaServerInfoService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误"+err.Error(), c)
		} else {
			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
