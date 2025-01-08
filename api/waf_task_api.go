package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"github.com/gin-gonic/gin"
)

type WafTaskApi struct {
}

func (w *WafTaskApi) AddApi(c *gin.Context) {
	var req request.WafTaskAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		/*cnt := wafTaskService.CheckIsExistApi(req)
		if cnt == 0 {
			err = wafTaskService.AddApi(req)
			if err == nil {
				response.OkWithMessage("添加成功", c)
			} else {
				response.FailWithMessage("添加失败", c)
			}
			return
		} else {
			response.FailWithMessage("当前记录已经存在", c)
			return
		}*/
		response.FailWithMessage("不允许操作", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafTaskApi) GetDetailApi(c *gin.Context) {
	var req request.WafTaskDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := TaskService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafTaskApi) GetListApi(c *gin.Context) {
	var req request.WafTaskSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		Task, total, _ := TaskService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      Task,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafTaskApi) DelApi(c *gin.Context) {
	var req request.WafTaskDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		/*err = wafTaskService.DelApi(req)
		if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
			response.FailWithMessage("请检测参数", c)
		} else if err != nil {
			response.FailWithMessage("发生错误", c)
		} else {
			response.OkWithMessage("删除成功", c)
		}*/
		response.FailWithMessage("不允许操作", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafTaskApi) ModifyApi(c *gin.Context) {
	var req request.WafTaskEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		/*err = wafTaskService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误"+err.Error(), c)
		} else {
			response.OkWithMessage("编辑成功", c)
		}*/
		response.FailWithMessage("不允许操作", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

func (w *WafTaskApi) ManualExecuteApi(c *gin.Context) {
	var req request.WafTaskDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := TaskService.GetDetailApi(req)
		if bean.Id == "" {
			response.FailWithMessage("记录为空", c)
		} else {
			//发送信息
			global.GWAF_CHAN_TASK <- bean.TaskMethod
			response.OkWithMessage("发起成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}
