package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/waftask"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafSystemConfigApi struct {
}

func (w *WafSystemConfigApi) AddApi(c *gin.Context) {
	var req request.WafSystemConfigAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafSystemConfigService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafSystemConfigService.AddApi(req)
			if err == nil {
				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前数据已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSystemConfigApi) GetDetailApi(c *gin.Context) {
	var req request.WafSystemConfigDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafSystemConfigService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSystemConfigApi) GetListApi(c *gin.Context) {
	var req request.WafSystemConfigSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafSystemConfigService.GetListApi(req)
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
func (w *WafSystemConfigApi) DelApi(c *gin.Context) {
	var req request.WafSystemConfigDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafSystemConfigService.DelApi(req)
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

func (w *WafSystemConfigApi) ModifyApi(c *gin.Context) {
	var req request.WafSystemConfigEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafSystemConfigService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			waftask.TaskLoadSetting(true)
			response.OkWithMessage("编辑成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
