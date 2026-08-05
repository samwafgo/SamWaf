package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"encoding/json"
	"errors"
	"gorm.io/gorm"
	"time"
)

type WafBatchTaskService struct{}

var WafBatchServiceApp = new(WafBatchTaskService)

func (receiver *WafBatchTaskService) AddApi(req request.BatchTaskAddReq) error {

	err := receiver.CheckIsExistApi(req.BatchTaskName)
	if err == nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return errors.New("任务名已存在")
	}
	if err = receiver.checkExtraConfig(req.BatchType, req.BatchExtraConfig); err != nil {
		return err
	}
	var bean = &model.BatchTask{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		BatchTaskName:      req.BatchTaskName,
		BatchHostCode:      req.BatchHostCode,
		BatchExecuteMethod: req.BatchExecuteMethod,
		BatchSource:        req.BatchSource,
		BatchSourceType:    req.BatchSourceType,
		BatchTriggerType:   req.BatchTriggerType,
		BatchType:          req.BatchType,
		BatchExtraConfig:   req.BatchExtraConfig,
		Remark:             req.Remark,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

// checkExtraConfig 保存前校验额外配置。
//
// IP组任务必须指向一个真实存在的组：留到执行时才发现配错，用户只能去翻日志
// 才知道定时任务一直在空跑，所以在这里就挡下来。
func (receiver *WafBatchTaskService) checkExtraConfig(batchType string, extraConfig string) error {
	if batchType != enums.BATCHTASK_IPGROUP {
		return nil
	}
	var config struct {
		GroupCode string `json:"group_code"`
	}
	if extraConfig != "" {
		if err := json.Unmarshal([]byte(extraConfig), &config); err != nil {
			return errors.New("额外配置不是合法的JSON:" + err.Error())
		}
	}
	if config.GroupCode == "" {
		return errors.New("请选择目标IP组")
	}
	var cnt int64
	global.GWAF_LOCAL_DB.Model(&model.IPGroup{}).
		Where("group_code = ? AND user_code = ? AND tenant_id = ?", config.GroupCode, global.GWAF_USER_CODE, global.GWAF_TENANT_ID).
		Count(&cnt)
	if cnt == 0 {
		return errors.New("目标IP组不存在")
	}
	return nil
}

func (receiver *WafBatchTaskService) CheckIsExistApi(batchName string) error {
	return global.GWAF_LOCAL_DB.First(&model.BatchTask{}, "batch_task_name = ?", batchName).Error
}

func (receiver *WafBatchTaskService) ModifyApi(req request.BatchTaskEditReq) error {

	var bean model.BatchTask
	global.GWAF_LOCAL_DB.Where("batch_task_name = ?", req.BatchTaskName).Find(&bean)
	if bean.Id != "" && bean.BatchTaskName != req.BatchTaskName {
		return errors.New("该任务已经存在")
	}
	if err := receiver.checkExtraConfig(req.BatchType, req.BatchExtraConfig); err != nil {
		return err
	}

	beanMap := map[string]interface{}{
		"BatchTaskName":      req.BatchTaskName,
		"BatchHostCode":      req.BatchHostCode,
		"BatchExecuteMethod": req.BatchExecuteMethod,
		"BatchSource":        req.BatchSource,
		"BatchSourceType":    req.BatchSourceType,
		"BatchTriggerType":   req.BatchTriggerType,
		"BatchType":          req.BatchType,
		"BatchExtraConfig":   req.BatchExtraConfig,
		"Remark":             req.Remark,
	}
	err := global.GWAF_LOCAL_DB.Model(model.BatchTask{}).Where("id = ?", req.Id).Updates(beanMap).Error
	return err
}

// GetDetailApi
func (receiver *WafBatchTaskService) GetDetailApi(req request.BatchTaskDetailReq) model.BatchTask {
	var bean model.BatchTask
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}

// GetDetailByIdApi
func (receiver *WafBatchTaskService) GetDetailByIdApi(id string) model.BatchTask {
	var bean model.BatchTask
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafBatchTaskService) GetListApi(req request.BatchTaskSearchReq) ([]model.BatchTask, int64, error) {
	var list []model.BatchTask
	var total int64 = 0
	var whereField = ""
	var whereValues []interface{}

	if len(req.BatchTaskName) > 0 {
		whereField += "batch_task_name like ?"
		whereValues = append(whereValues, "%"+req.BatchTaskName+"%")
	}

	global.GWAF_LOCAL_DB.Model(&model.BatchTask{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.BatchTask{}).Where(whereField, whereValues...).Count(&total)
	return list, total, nil
}

func (receiver *WafBatchTaskService) GetAllCronListInner() ([]model.BatchTask, int64, error) {
	var list []model.BatchTask
	var total int64 = 0
	var whereField = "batch_trigger_type = ?"
	var whereValues []interface{}
	whereValues = append(whereValues, "cron")

	global.GWAF_LOCAL_DB.Model(&model.BatchTask{}).Where(whereField, whereValues...).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.BatchTask{}).Where(whereField, whereValues...).Count(&total)
	return list, total, nil
}

func (receiver *WafBatchTaskService) DelApi(req request.BatchTaskDeleteReq) error {
	var bean model.BatchTask
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.BatchTask{}).Error
	return err
}
