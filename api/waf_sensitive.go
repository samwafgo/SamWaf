package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafSensitiveApi struct {
}

func (w *WafSensitiveApi) AddApi(c *gin.Context) {
	var req request.WafSensitiveAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafSensitiveService.CheckIsExistApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = wafSensitiveService.AddApi(req)
			if err == nil {
				w.NotifyWaf()
				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前敏感词已经存在", c)
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSensitiveApi) GetDetailApi(c *gin.Context) {
	var req request.WafSensitiveDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafSensitiveService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSensitiveApi) GetListApi(c *gin.Context) {
	var req request.WafSensitiveSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		sensitiveList, total, _ := wafSensitiveService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      sensitiveList,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafSensitiveApi) DelSensitiveApi(c *gin.Context) {
	var req request.WafSensitiveDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafSensitiveService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			w.NotifyWaf()
			response.OkWithMessage("删除成功", c)
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafSensitiveApi) ModifySensitiveApi(c *gin.Context) {
	var req request.WafSensitiveEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafSensitiveService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {
			w.NotifyWaf()
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
func (w *WafSensitiveApi) NotifyWaf() {
	global.GWAF_CHAN_SENSITIVE <- 1
}