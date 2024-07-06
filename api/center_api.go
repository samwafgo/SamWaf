package api

import (
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type CenterApi struct {
}

func (w *CenterApi) UpdateApi(c *gin.Context) {
	var req request.CenterClientUpdateReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = CenterService.CheckIsExistApi(req)
		req.ClientIP = c.RemoteIP()
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			err = CenterService.AddApi(req)
			if err == nil {
				response.OkWithMessage("添加成功", c)
			} else {

				response.FailWithMessage("添加失败", c)
			}
			return
		} else {

			err = CenterService.ModifyApi(req)
			if err == nil {
				response.OkWithMessage("更新成功", c)
			} else {

				response.FailWithMessage("更新失败", c)
			}
			return
		}

	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *CenterApi) GetDetailApi(c *gin.Context) {
	var req request.CenterClientDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := CenterService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *CenterApi) GetListApi(c *gin.Context) {
	var req request.CenterClientSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		beans, total, _ := CenterService.GetListApi(req)
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
