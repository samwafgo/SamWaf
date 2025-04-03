package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"errors"
	uuid "github.com/satori/go.uuid"
	"time"
)

type WafTaskService struct{}

var WafTaskServiceApp = new(WafTaskService)

func (receiver *WafTaskService) AddApi(req request.WafTaskAddReq) error {
	var bean = &model.Task{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},

		TaskName:   req.TaskName,
		TaskUnit:   req.TaskUnit,
		TaskValue:  req.TaskValue,
		TaskAt:     req.TaskAt,
		TaskMethod: req.TaskMethod,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafTaskService) Add(req model.Task) error {
	var bean = &model.Task{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},

		TaskName:   req.TaskName,
		TaskUnit:   req.TaskUnit,
		TaskValue:  req.TaskValue,
		TaskAt:     req.TaskAt,
		TaskMethod: req.TaskMethod,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafTaskService) CheckIsExistApi(req request.WafTaskAddReq) int {
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.TaskName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " task_name=? "
	}

	//where字段赋值
	if len(req.TaskName) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, req.TaskName)
		}
	}

	global.GWAF_LOCAL_DB.Model(&model.Task{}).Where(whereField, whereValues...).Count(&total)
	return int(total)
}

func (receiver *WafTaskService) CheckIsExist(taskMethod string) int {
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(taskMethod) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " task_method=? "
	}

	//where字段赋值
	if len(taskMethod) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, taskMethod)
		}
	}

	global.GWAF_LOCAL_DB.Model(&model.Task{}).Where(whereField, whereValues...).Count(&total)
	return int(total)
}

func (receiver *WafTaskService) ModifyApi(req request.WafTaskEditReq) error {
	// 根据唯一字段生成查询条件（只有在UniFields不为空时才进行存在性检查）

	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.TaskName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " task_name=? "
	}

	//where字段赋值

	if len(req.TaskName) > 0 {
		whereValues = append(whereValues, req.TaskName)
	}

	global.GWAF_LOCAL_DB.Model(&model.Task{}).Where(whereField, whereValues...).Count(&total)
	// 查询是否已存在记录
	var bean model.Task
	global.GWAF_LOCAL_DB.Model(&model.Task{}).Where(whereField, whereValues...).Limit(1).Find(&bean)

	if int(total) > 0 && bean.Id != "" && bean.Id != req.Id {
		return errors.New("当前记录已经存在")
	}

	beanMap := map[string]interface{}{

		"TaskName":   req.TaskName,
		"TaskUnit":   req.TaskUnit,
		"TaskAt":     req.TaskAt,
		"TaskMethod": req.TaskMethod,
		"TaskValue":  req.TaskValue,

		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Task{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}
func (receiver *WafTaskService) GetDetailApi(req request.WafTaskDetailReq) model.Task {
	var bean model.Task
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafTaskService) GetDetailByIdApi(id string) model.Task {
	var bean model.Task
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafTaskService) GetListApi(req request.WafTaskSearchReq) ([]model.Task, int64, error) {
	var list []model.Task
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.Task{}).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.Task{}).Count(&total)

	return list, total, nil
}
func (receiver *WafTaskService) GetList() ([]model.Task, int64, error) {
	var list []model.Task
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.Task{}).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.Task{}).Count(&total)

	return list, total, nil
}
func (receiver *WafTaskService) DelApi(req request.WafTaskDelReq) error {
	var bean model.Task
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.Task{}).Error
	return err
}
func (receiver *WafTaskService) DelByMethod(taskMethod string) error {
	var bean model.Task
	err := global.GWAF_LOCAL_DB.Where("task_method = ?", taskMethod).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("task_method = ?", taskMethod).Delete(model.Task{}).Error
	return err
}
