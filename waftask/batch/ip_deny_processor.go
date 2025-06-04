package batch

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/spec"
	"fmt"
	"time"
)

// IPDenyProcessor 黑名单IP处理器
type IPDenyProcessor struct{}

// ProcessBatch 处理一批IP
func (p *IPDenyProcessor) ProcessBatch(items []string, task model.BatchTask, progress *BatchProgress) bool {
	if len(items) == 0 {
		return false
	}

	logName := "BatchTask-IPDenyBatch"
	zlog.Info(logName, fmt.Sprintf("处理黑名单批次，包含 %d 个IP", len(items)))

	// 获取已存在的记录
	existMap := p.GetExistingItems(items, task, nil)

	// 根据执行方法处理
	if task.BatchExecuteMethod == enums.BATCHTASK_EXECUTEMETHODAPPEND {
		return p.processAppendBatch(items, existMap, task, logName, progress)
	} else if task.BatchExecuteMethod == enums.BATCHTASK_EXECUTEMETHODOVERWRITE {
		return p.processOverwriteBatch(items, existMap, task, logName, progress)
	}

	return false
}

// GetExistingItems 获取已存在的IP记录
func (p *IPDenyProcessor) GetExistingItems(items []string, task model.BatchTask, config interface{}) map[string]interface{} {
	existMap := make(map[string]interface{})
	var existIPs []model.IPBlockList

	// 使用IN查询一次性获取所有已存在的记录
	global.GWAF_LOCAL_DB.Where("host_code = ? AND ip IN (?)", task.BatchHostCode, items).Find(&existIPs)

	// 将已存在的IP放入map中，方便快速查找
	for _, ip := range existIPs {
		existMap[ip.Ip] = ip
	}

	return existMap
}

// NotifyEngine 通知引擎更新
func (p *IPDenyProcessor) NotifyEngine(task model.BatchTask) {
	var ipBlocks []model.IPBlockList
	global.GWAF_LOCAL_DB.Where("host_code = ? ", task.BatchHostCode).Find(&ipBlocks)
	var chanInfo = spec.ChanCommonHost{
		HostCode: task.BatchHostCode,
		Type:     enums.ChanTypeBlockIP,
		Content:  ipBlocks,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}

// processAppendBatch 处理追加模式的批次
func (p *IPDenyProcessor) processAppendBatch(items []string, existMap map[string]interface{}, task model.BatchTask, logName string, progress *BatchProgress) bool {
	// 收集需要插入的记录
	var toInsert []model.IPBlockList
	for _, ip := range items {
		// 如果IP不存在，则添加到待插入列表
		if _, exists := existMap[ip]; !exists {
			toInsert = append(toInsert, model.IPBlockList{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   global.GWAF_USER_CODE,
					Tenant_ID:   global.GWAF_TENANT_ID,
					CREATE_TIME: customtype.JsonTime(time.Now()),
					UPDATE_TIME: customtype.JsonTime(time.Now()),
				},
				HostCode: task.BatchHostCode,
				Ip:       ip,
				Remarks:  time.Now().Format("20060102") + "批量导入 任务ID:" + task.Id,
			})
		}
	}

	// 批量插入新记录
	if len(toInsert) > 0 {
		tx := global.GWAF_LOCAL_DB.Begin()
		if err := tx.Create(&toInsert).Error; err != nil {
			tx.Rollback()
			zlog.Error(logName, "批量插入黑名单IP失败: "+err.Error())
			return false
		}
		tx.Commit()

		zlog.Info(logName, fmt.Sprintf("成功插入 %d 条黑名单IP记录", len(toInsert)))
		// 更新进度统计
		progress.AddInserted(len(toInsert))
		return len(toInsert) > 0
	}

	return false
}

// processOverwriteBatch 处理覆写模式的批次
func (p *IPDenyProcessor) processOverwriteBatch(items []string, existMap map[string]interface{}, task model.BatchTask, logName string, progress *BatchProgress) bool {
	// 收集需要插入和更新的记录
	var toInsert []model.IPBlockList
	var toUpdate []model.IPBlockList

	for _, ip := range items {
		if existIP, exists := existMap[ip]; exists {
			// 已存在，需要更新
			ipRecord := existIP.(model.IPBlockList)
			ipRecord.Remarks = time.Now().Format("20060102") + "批量导入编辑 任务ID:" + task.Id
			ipRecord.UPDATE_TIME = customtype.JsonTime(time.Now())
			toUpdate = append(toUpdate, ipRecord)
		} else {
			// 不存在，需要插入
			toInsert = append(toInsert, model.IPBlockList{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   global.GWAF_USER_CODE,
					Tenant_ID:   global.GWAF_TENANT_ID,
					CREATE_TIME: customtype.JsonTime(time.Now()),
					UPDATE_TIME: customtype.JsonTime(time.Now()),
				},
				HostCode: task.BatchHostCode,
				Ip:       ip,
				Remarks:  time.Now().Format("20060102") + "批量导入 任务ID:" + task.Id,
			})
		}
	}

	// 开始事务
	tx := global.GWAF_LOCAL_DB.Begin()
	hasChanges := false

	// 批量插入新记录
	if len(toInsert) > 0 {
		if err := tx.Create(&toInsert).Error; err != nil {
			tx.Rollback()
			zlog.Error(logName, "批量插入黑名单IP失败: "+err.Error())
			return false
		}
		zlog.Info(logName, fmt.Sprintf("成功插入 %d 条黑名单IP记录", len(toInsert)))
		// 更新进度统计
		progress.AddInserted(len(toInsert))
		hasChanges = true
	}

	// 批量更新已存在的记录
	if len(toUpdate) > 0 {
		for _, record := range toUpdate {
			if err := tx.Model(&model.IPBlockList{}).Where("id = ?", record.Id).Updates(map[string]interface{}{
				"Remarks":     record.Remarks,
				"UPDATE_TIME": record.UPDATE_TIME,
			}).Error; err != nil {
				tx.Rollback()
				zlog.Error(logName, "批量更新黑名单IP失败: "+err.Error())
				return false
			}
		}
		zlog.Info(logName, fmt.Sprintf("成功更新 %d 条黑名单IP记录", len(toUpdate)))
		// 更新进度统计
		progress.AddUpdated(len(toUpdate))
		hasChanges = true
	}

	// 提交事务
	tx.Commit()
	return hasChanges
}
