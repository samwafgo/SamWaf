package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	response2 "SamWaf/model/response"
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
		if global.GDATA_CURRENT_CHANGE {
			//如果正在切换库 跳过
			response.FailWithMessage("正在切换数据库请等待", c)
			return
		}
		wafLogs, total, err2 := wafLogService.GetListApi(req)
		if err2 != nil {
			response.FailWithMessage("访问列表失败:"+err2.Error(), c)
		} else {
			response.OkWithDetailed(response.PageResult{
				List:      wafLogs,
				Total:     total,
				PageIndex: req.PageIndex,
				PageSize:  req.PageSize,
			}, "获取成功", c)
		}

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

func (w *WafLogAPi) GetAllShareDbApi(c *gin.Context) {
	wafShareList, _ := wafShareDbService.GetAllShareDbApi()
	allShareDbRep := make([]response2.AllShareDbRep, len(wafShareList)) // 创建数组
	for i, _ := range wafShareList {

		allShareDbRep[i] = response2.AllShareDbRep{
			StartTime: wafShareList[i].StartTime,
			EndTime:   wafShareList[i].EndTime,
			FileName:  wafShareList[i].FileName,
			Cnt:       wafShareList[i].Cnt,
		}

	}
	response.OkWithDetailed(allShareDbRep, "获取成功", c)
}
