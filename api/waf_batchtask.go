package api

import (
	"SamWaf/enums"
	"SamWaf/model/common/response"
	"SamWaf/model/request"
	"SamWaf/waftask"
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WafBatchTaskApi struct{}

// AddBatchTaskApi 添加自动任务
func (s *WafBatchTaskApi) AddBatchTaskApi(c *gin.Context) {
	var req request.BatchTaskAddReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafBatchTaskService.AddApi(req)
		if err == nil {
			response.OkWithMessage("添加成功", c)
		} else {
			response.FailWithMessage("添加失败:"+err.Error(), c)
		}
		return
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetBatchTaskDetailApi 获取详情
func (s *WafBatchTaskApi) GetBatchTaskDetailApi(c *gin.Context) {
	var req request.BatchTaskDetailReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafBatchTaskService.GetDetailApi(req)
		response.OkWithDetailed(bean, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// GetBatchTaskListApi 获取任务列表
func (s *WafBatchTaskApi) GetBatchTaskListApi(c *gin.Context) {
	var req request.BatchTaskSearchReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		list, total, _ := wafBatchTaskService.GetListApi(req)
		response.OkWithDetailed(response.PageResult{
			List:      list,
			Total:     total,
			PageIndex: req.PageIndex,
			PageSize:  req.PageSize,
		}, "获取成功", c)
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// DelBatchTaskApi 删除任务
func (s *WafBatchTaskApi) DelBatchTaskApi(c *gin.Context) {
	var req request.BatchTaskDeleteReq
	err := c.ShouldBind(&req)
	if err == nil {
		err = wafBatchTaskService.DelApi(req)
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

// ModifyBatchTaskApi 编辑任务
func (s *WafBatchTaskApi) ModifyBatchTaskApi(c *gin.Context) {
	var req request.BatchTaskEditReq
	err := c.ShouldBindJSON(&req)
	if err == nil {
		err = wafBatchTaskService.ModifyApi(req)
		if err != nil {
			response.FailWithMessage("编辑发生错误", c)
		} else {

			response.OkWithMessage("编辑成功", c)
		}
	} else {
		response.FailWithMessage("解析失败", c)
	}
}

// ManualBatchTaskApi 手工执行任务
func (s *WafBatchTaskApi) ManualBatchTaskApi(c *gin.Context) {
	var req request.BatchTaskManualReq
	err := c.ShouldBind(&req)
	if err == nil {
		bean := wafBatchTaskService.GetDetailByIdApi(req.Id)
		switch bean.BatchType {
		case enums.BATCHTASK_IPALLOW:
			waftask.IPAllowBatch(bean)
			break
		case enums.BATCHTASK_IPDENY:
			waftask.IPDenyBatch(bean)
			break
		case enums.BATCHTASK_SENSITIVE:
			waftask.SensitiveBatch(bean)
		}
		response.OkWithMessage("手工执行任务成功", c)
	} else {
		response.FailWithMessage("手工执行任务失败", c)
	}
}
