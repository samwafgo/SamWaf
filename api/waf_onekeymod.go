package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/wafonekey"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafOneKeyModApi struct {
}

func (w *WafOneKeyModApi) GetDetailApi(c *gin.Context) {
	var req request.WafOneKeyModDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafOneKeyModService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafOneKeyModApi) GetListApi(c *gin.Context) {
	var req request.WafOneKeyModSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := wafOneKeyModService.GetListApi(req)
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
func (w *WafOneKeyModApi) DelApi(c *gin.Context) {
	var req request.WafOneKeyModDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafOneKeyModService.DelApi(req)
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

func (w *WafOneKeyModApi) DoOneKeyModifyApi(c *gin.Context) {
	var req request.WafDoOneKeyModReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err, s := wafonekey.OneKeyModifyBt(req.FilePath)
		if err != nil {
			response.FailWithMessage("修改失败 "+err.Error(), c)
		} else {
			response.OkWithMessage(s, c)
		}

	} else {
		response.FailWithMessage("修改失败", c)
	}
}
func (w *WafOneKeyModApi) RestoreApi(c *gin.Context) {
	var req request.WafOneKeyModRestoreReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafonekey.RestoreOneKeyMod(req.Id)
		if err != nil {
			response.FailWithMessage("还原失败 "+err.Error(), c)
		} else {
			response.OkWithMessage("还原成功 请重启在宝塔面板上进行Nginx重启", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
