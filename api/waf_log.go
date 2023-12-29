package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"github.com/gin-gonic/gin"
)

type WafLogAPi struct {
}

func (w *WafLogAPi) GetDetailApi(c *gin.Context) {
	var req request.WafAttackLogDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		if global.GDATA_CURRENT_CHANGE {
			//如果正在切换库 跳过
			response.FailWithMessage("正在切换数据库请等待", c)
			return
		}
		wafLog, _ := wafLogService.GetDetailApi(req)
		response.OkWithDetailed(wafLog, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafLogAPi) GetListApi(c *gin.Context) {
	var req request.WafAttackLogSearch
	err := c.ShouldBindJSON(&req)
	if err == nil {
		/*//TOOD 模拟意外退出

		os.Exit(-1) //退出进程*/
		if global.GDATA_CURRENT_CHANGE {
			//如果正在切换库 跳过
			response.FailWithMessage("正在切换数据库请等待", c)
			return
		}
		wafLogs, total, _ := wafLogService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      wafLogs,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
func (w *WafLogAPi) GetListByHostCodeApi(c *gin.Context) {
	var req request.WafAttackLogSearch
	err := c.ShouldBind(&req)
	if err == nil {
		if global.GDATA_CURRENT_CHANGE {
			//如果正在切换库 跳过
			response.FailWithMessage("正在切换数据库请等待", c)
			return
		}
		wafLogs, total, _ := wafLogService.GetListByHostCodeApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      wafLogs,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
