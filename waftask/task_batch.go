package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/model"
	"SamWaf/service/waf_service"
	"SamWaf/waftask/batch"
)

var (
	wafBatchTaskService = waf_service.WafBatchServiceApp
)

/*
*
批量任务
*/
func BatchTask() {
	innerLogName := "BatchTask"
	zlog.Info(innerLogName, "准备进行自动执行批量任务")

	batchTaskList, size, err := wafBatchTaskService.GetAllCronListInner()
	if err != nil {
		zlog.Error(innerLogName, "批量任务:", err)
		return
	}
	if size <= 0 {
		zlog.Info(innerLogName, "没有需要批量执行的任务")
		return
	}
	for _, batchTask := range batchTaskList {

		switch batchTask.BatchType {
		case enums.BATCHTASK_IPALLOW:
			IPAllowBatch(batchTask)
			break
		case enums.BATCHTASK_IPDENY:
			IPDenyBatch(batchTask)
			break
		case enums.BATCHTASK_SENSITIVE:
			SensitiveBatch(batchTask)
			break
		}
		zlog.Info(innerLogName, "批量已处理完")

	}
}

// IPAllowBatch 白名单IP批量处理
func IPAllowBatch(task model.BatchTask) {
	processor := &batch.IPAllowProcessor{}
	config := batch.BatchProcessorConfig{
		BatchSize: 1000,
		LogPrefix: "BatchTask-IPAllowBatch",
	}
	batch.ProcessBatchTask(task, processor, config)
}

// IPDenyBatch 黑名单IP批量处理
func IPDenyBatch(task model.BatchTask) {
	processor := &batch.IPDenyProcessor{}
	config := batch.BatchProcessorConfig{
		BatchSize: 1000,
		LogPrefix: "BatchTask-IPDenyBatch",
	}
	batch.ProcessBatchTask(task, processor, config)
}

// SensitiveBatch 敏感词批量处理
func SensitiveBatch(task model.BatchTask) {
	processor := &batch.SensitiveProcessor{}
	config := batch.BatchProcessorConfig{
		BatchSize: 1000,
		LogPrefix: "BatchTask-SensitiveBatch",
	}
	batch.ProcessBatchTask(task, processor, config)
}
