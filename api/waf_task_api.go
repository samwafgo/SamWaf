package api

import (
	"SamWaf/global"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"errors"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafTaskApi struct {
}

// AddApi 新增定时任务
// @Summary      新增定时任务
// @Description  新增一个WAF定时任务配置
// @Tags         定时任务管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafTaskAddReq  true  "任务配置"
// @Success      200   {object}  response.Response  "添加成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/task/add [post]
func (w *WafTaskApi) AddApi(c *gin.Context) {
	var req request.WafTaskAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		cnt := wafTaskService.CheckIsExistApi(req)
		if cnt == 0 {
			err = wafTaskService.AddApi(req)
			if err == nil {
				response.OkWithMessage("添加成功", c)
			} else {
				response.FailWithMessage("添加失败", c)
			}
		} else {
			response.FailWithMessage("当前记录已经存在", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetDetailApi 获取定时任务详情
// @Summary      获取定时任务详情
// @Description  根据ID获取定时任务详情
// @Tags         定时任务管理
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "任务ID"
// @Success      200  {object}  response.Response  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/task/detail [get]
func (w *WafTaskApi) GetDetailApi(c *gin.Context) {
	var req request.WafTaskDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafTaskService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetListApi 获取定时任务列表
// @Summary      获取定时任务列表
// @Description  分页查询定时任务列表
// @Tags         定时任务管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafTaskSearchReq  true  "分页查询参数"
// @Success      200   {object}  response.Response{data=response.PageResult}  "获取成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/task/list [post]
func (w *WafTaskApi) GetListApi(c *gin.Context) {
	var req request.WafTaskSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		Task, total, _ := wafTaskService.GetListApi(req)
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

// DelApi 删除定时任务
// @Summary      删除定时任务
// @Description  根据ID删除定时任务配置
// @Tags         定时任务管理
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "任务ID"
// @Success      200  {object}  response.Response  "删除成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/task/del [get]
func (w *WafTaskApi) DelApi(c *gin.Context) {
	var req request.WafTaskDelReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafTaskService.DelApi(req)
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

// ModifyApi 编辑定时任务
// @Summary      编辑定时任务
// @Description  修改定时任务配置并重新调度
// @Tags         定时任务管理
// @Accept       json
// @Produce      json
// @Param        data  body      request.WafTaskEditReq  true  "任务配置"
// @Success      200   {object}  response.Response  "编辑成功，任务已重新调度"
// @Security     ApiKeyAuth
// @Router       /wafhost/task/edit [post]
func (w *WafTaskApi) ModifyApi(c *gin.Context) {
	var req request.WafTaskEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		// 更新数据库中的任务
		err = wafTaskService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误"+err.Error(), c)
			return
		}

		// 获取更新后的任务信息
		newTask := wafTaskService.GetDetailByIdApi(req.Id)

		// 通过channel通知调度器重新加载任务
		// 使用新任务的配置进行重新调度
		global.GWAF_CHAN_TASK_RELOAD <- newTask

		response.OkWithMessage("编辑成功，任务已重新调度", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ManualExecuteApi 手动执行定时任务
// @Summary      手动执行定时任务
// @Description  根据ID立即手动触发执行一次定时任务
// @Tags         定时任务管理
// @Accept       json
// @Produce      json
// @Param        id  query     string  true  "任务ID"
// @Success      200  {object}  response.Response  "发起成功"
// @Security     ApiKeyAuth
// @Router       /wafhost/task/manual_exec [get]
func (w *WafTaskApi) ManualExecuteApi(c *gin.Context) {
	var req request.WafTaskDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafTaskService.GetDetailApi(req)
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
