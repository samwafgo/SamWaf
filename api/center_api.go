package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type CenterApi struct {
}

func (w *CenterApi) UpdateApi(c *gin.Context) {
	if global.GWAF_CENTER_ENABLE == "true" {
		response.FailWithMessage("单台服务器不能同时为客户端和服务端", c)
		return
	}
	clientCount, err2 := CenterService.CountApi()
	if err2 != nil {
		response.FailWithMessage("异常1", c)
		return
	}

	if clientCount > global.GWAF_REG_FREE_COUNT {
		response.FailWithMessage("授权数量超额", c)
		return
	}
	global.GWAF_REG_CUR_CLIENT_COUNT = clientCount

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
