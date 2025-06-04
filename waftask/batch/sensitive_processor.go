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
	"encoding/json"
	"fmt"
	"time"
)

// SensitiveConfig 敏感词批量任务额外配置
type SensitiveConfig struct {
	CheckDirection string `json:"check_direction"` // 敏感词检测方向 in,out,all
	Action         string `json:"action"`          // 敏感词检测后动作 deny,replace
}

// SensitiveProcessor 敏感词处理器
type SensitiveProcessor struct{}

// ProcessBatch 处理一批敏感词
func (p *SensitiveProcessor) ProcessBatch(items []string, task model.BatchTask, progress *BatchProgress) bool {
	if len(items) == 0 {
		return false
	}

	logName := "BatchTask-SensitiveBatch"
	zlog.Info(logName, fmt.Sprintf("处理敏感词批次，包含 %d 个敏感词", len(items)))

	// 解析额外配置
	var config SensitiveConfig
	if task.BatchExtraConfig != "" {
		if err := json.Unmarshal([]byte(task.BatchExtraConfig), &config); err != nil {
			zlog.Error(logName, "解析敏感词配置失败: "+err.Error())
			return false
		}
	} else {
		// 默认配置
		config.CheckDirection = "out"
		config.Action = "replace"
	}

	// 获取已存在的记录
	existMap := p.GetExistingItems(items, task, config)

	// 根据执行方法处理
	if task.BatchExecuteMethod == enums.BATCHTASK_EXECUTEMETHODAPPEND {
		return p.processAppendBatch(items, existMap, task, config, logName, progress)
	} else if task.BatchExecuteMethod == enums.BATCHTASK_EXECUTEMETHODOVERWRITE {
		return p.processOverwriteBatch(items, existMap, task, config, logName, progress)
	}

	return false
}

// GetExistingItems 获取已存在的敏感词记录
func (p *SensitiveProcessor) GetExistingItems(items []string, task model.BatchTask, config interface{}) map[string]interface{} {
	existMap := make(map[string]interface{})
	var existSensitives []model.Sensitive

	sensitiveConfig := config.(SensitiveConfig)
	// 使用IN查询一次性获取所有已存在的记录
	global.GWAF_LOCAL_DB.Where("content IN (?) and check_direction = ?", items, sensitiveConfig.CheckDirection).Find(&existSensitives)

	// 将已存在的敏感词放入map中，方便快速查找
	for _, sensitive := range existSensitives {
		existMap[sensitive.Content] = sensitive
	}

	return existMap
}

// NotifyEngine 通知引擎更新
func (p *SensitiveProcessor) NotifyEngine(task model.BatchTask) {
	var sensitives []model.Sensitive
	global.GWAF_LOCAL_DB.Find(&sensitives)
	var chanInfo = spec.ChanCommonHost{
		HostCode: task.BatchHostCode,
		Type:     enums.ChanTypeSensitive,
		Content:  sensitives,
	}
	global.GWAF_CHAN_MSG <- chanInfo
}

// processAppendBatch 处理追加模式的批次
func (p *SensitiveProcessor) processAppendBatch(items []string, existMap map[string]interface{}, task model.BatchTask, config SensitiveConfig, logName string, progress *BatchProgress) bool {
	// 收集需要插入的记录
	var toInsert []model.Sensitive
	for _, content := range items {
		// 如果敏感词不存在，则添加到待插入列表
		if _, exists := existMap[content]; !exists {
			toInsert = append(toInsert, model.Sensitive{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   global.GWAF_USER_CODE,
					Tenant_ID:   global.GWAF_TENANT_ID,
					CREATE_TIME: customtype.JsonTime(time.Now()),
					UPDATE_TIME: customtype.JsonTime(time.Now()),
				},
				CheckDirection: config.CheckDirection,
				Action:         config.Action,
				Content:        content,
				Remarks:        time.Now().Format("20060102") + "批量导入 任务ID:" + task.Id,
			})
		}
	}

	// 批量插入新记录
	if len(toInsert) > 0 {
		tx := global.GWAF_LOCAL_DB.Begin()
		if err := tx.Create(&toInsert).Error; err != nil {
			tx.Rollback()
			zlog.Error(logName, "批量插入敏感词失败: "+err.Error())
			return false
		}
		tx.Commit()

		zlog.Info(logName, fmt.Sprintf("成功插入 %d 条敏感词记录", len(toInsert)))
		// 更新进度统计
		progress.AddInserted(len(toInsert))
		return len(toInsert) > 0
	}

	return false
}

// processOverwriteBatch 处理覆写模式的批次
func (p *SensitiveProcessor) processOverwriteBatch(items []string, existMap map[string]interface{}, task model.BatchTask, config SensitiveConfig, logName string, progress *BatchProgress) bool {
	// 收集需要插入和更新的记录
	var toInsert []model.Sensitive
	var toUpdate []model.Sensitive

	for _, content := range items {
		if existSensitive, exists := existMap[content]; exists {
			// 已存在，需要更新
			sensitiveRecord := existSensitive.(model.Sensitive)
			sensitiveRecord.CheckDirection = config.CheckDirection
			sensitiveRecord.Action = config.Action
			sensitiveRecord.Remarks = time.Now().Format("20060102") + "批量导入编辑 任务ID:" + task.Id
			sensitiveRecord.UPDATE_TIME = customtype.JsonTime(time.Now())
			toUpdate = append(toUpdate, sensitiveRecord)
		} else {
			// 不存在，需要插入
			toInsert = append(toInsert, model.Sensitive{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   global.GWAF_USER_CODE,
					Tenant_ID:   global.GWAF_TENANT_ID,
					CREATE_TIME: customtype.JsonTime(time.Now()),
					UPDATE_TIME: customtype.JsonTime(time.Now()),
				},
				CheckDirection: config.CheckDirection,
				Action:         config.Action,
				Content:        content,
				Remarks:        time.Now().Format("20060102") + "批量导入 任务ID:" + task.Id,
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
			zlog.Error(logName, "批量插入敏感词失败: "+err.Error())
			return false
		}
		zlog.Info(logName, fmt.Sprintf("成功插入 %d 条敏感词记录", len(toInsert)))
		// 更新进度统计
		progress.AddInserted(len(toInsert))
		hasChanges = true
	}

	// 批量更新已存在的记录
	if len(toUpdate) > 0 {
		for _, record := range toUpdate {
			if err := tx.Model(&model.Sensitive{}).Where("id = ?", record.Id).Updates(map[string]interface{}{
				"CheckDirection": record.CheckDirection,
				"Action":         record.Action,
				"Remarks":        record.Remarks,
				"UPDATE_TIME":    record.UPDATE_TIME,
			}).Error; err != nil {
				tx.Rollback()
				zlog.Error(logName, "批量更新敏感词失败: "+err.Error())
				return false
			}
		}
		zlog.Info(logName, fmt.Sprintf("成功更新 %d 条敏感词记录", len(toUpdate)))
		// 更新进度统计
		progress.AddUpdated(len(toUpdate))
		hasChanges = true
	}

	// 提交事务
	tx.Commit()
	return hasChanges
}
