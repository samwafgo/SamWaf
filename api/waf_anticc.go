package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafAntiCCApi struct {
}

func (w *WafAntiCCApi) AddApi(c *gin.Context) {
	var req request.WafAntiCCAddReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafAntiCCService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafAntiCCService.AddApi(req)
			if err == nil {

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
func (w *WafAntiCCApi) GetDetailApi(c *gin.Context) {
	var req request.WafAntiCCDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafAntiCCService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafAntiCCApi) GetListApi(c *gin.Context) {
	var req request.WafAntiCCSearchReq
	err := c.ShouldBind(&req)
	if err == nil {
		beans, total, _ := wafAntiCCService.GetListApi(req)
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
func (w *WafAntiCCApi) DelAntiCCApi(c *gin.Context) {
	var req request.WafAntiCCDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafAntiCCService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			response.FailWithMessage("删除成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafAntiCCApi) ModifyAntiCCApi(c *gin.Context) {
	var req request.WafAntiCCEditReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafAntiCCService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			response.OkWithMessage("编辑成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
