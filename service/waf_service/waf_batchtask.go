package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
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

func (receiver *WafBatchTaskService) CheckIsExistApi(batchName string) error {
	return global.GWAF_LOCAL_DB.First(&model.BatchTask{}, "batch_task_name = ?", batchName).Error
}

func (receiver *WafBatchTaskService) ModifyApi(req request.BatchTaskEditReq) error {

	var bean model.BatchTask
	global.GWAF_LOCAL_DB.Where("batch_task_name = ?", req.BatchTaskName).Find(&bean)
	if bean.Id != "" && bean.BatchTaskName != req.BatchTaskName {
		return errors.New("该任务已经存在")
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
