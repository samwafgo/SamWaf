package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"errors"
	"time"
)

type WafSensitiveService struct{}

var WafSensitiveServiceApp = new(WafSensitiveService)

func (receiver *WafSensitiveService) AddApi(req request.WafSensitiveAddReq) error {
	var bean = &model.Sensitive{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		CheckDirection: req.CheckDirection,
		Action:         req.Action,
		Content:        req.Content,
		Remarks:        req.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafSensitiveService) CheckIsExistApi(req request.WafSensitiveAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.Sensitive{}, "content= ?",
		req.Content).Error
}
func (receiver *WafSensitiveService) ModifyApi(req request.WafSensitiveEditReq) error {
	var bean model.Sensitive
	global.GWAF_LOCAL_DB.Where("and content= ?",
		req.Content).Find(&bean)
	if bean.Id != "" && bean.Content != req.Content {
		return errors.New("当前敏感词已经存在")
	}
	beanMap := map[string]interface{}{
		"CheckDirection": req.CheckDirection,
		"Action":         req.Action,
		"Content":        req.Content,
		"Remarks":        req.Remarks,
		"UPDATE_TIME":    customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.Sensitive{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}
func (receiver *WafSensitiveService) GetDetailApi(req request.WafSensitiveDetailReq) model.Sensitive {
	var bean model.Sensitive
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafSensitiveService) GetDetailByIdApi(id string) model.Sensitive {
	var bean model.Sensitive
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafSensitiveService) GetListApi(req request.WafSensitiveSearchReq) ([]model.Sensitive, int64, error) {
	var list []model.Sensitive
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.Content) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " content like ? "
	}
	if len(req.Remarks) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " remarks like ? "
	}
	//where字段赋值
	if len(req.Content) > 0 {
		whereValues = append(whereValues, "%"+req.Content+"%")
	}
	if len(req.Remarks) > 0 {
		whereValues = append(whereValues, "%"+req.Remarks+"%")
	}
	global.GWAF_LOCAL_DB.Model(&model.Sensitive{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.Sensitive{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafSensitiveService) DelApi(req request.WafSensitiveDelReq) error {
	var bean model.Sensitive
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.Sensitive{}).Error
	return err
}

// BatchDelApi 批量删除指定ID的敏感词
func (receiver *WafSensitiveService) BatchDelApi(req request.WafSensitiveBatchDelReq) error {
	if len(req.Ids) == 0 {
		return errors.New("删除ID列表不能为空")
	}

	// 先检查所有ID是否存在
	var count int64
	err := global.GWAF_LOCAL_DB.Model(&model.Sensitive{}).Where("id IN ?", req.Ids).Count(&count).Error
	if err != nil {
		return err
	}

	if count != int64(len(req.Ids)) {
		return errors.New("部分ID不存在")
	}

	// 执行批量删除
	err = global.GWAF_LOCAL_DB.Where("id IN ?", req.Ids).Delete(&model.Sensitive{}).Error
	return err
}

// DelAllApi 删除所有敏感词
func (receiver *WafSensitiveService) DelAllApi(req request.WafSensitiveDelAllReq) error {
	// 构建查询条件
	query := global.GWAF_LOCAL_DB.Model(&model.Sensitive{}).
		Where("user_code = ? AND tenant_id = ?", global.GWAF_USER_CODE, global.GWAF_TENANT_ID)

	// 如果指定了检测方向，添加过滤条件
	if req.CheckDirection != "" {
		query = query.Where("check_direction = ?", req.CheckDirection)
	}

	// 先检查是否存在记录
	var count int64
	err := query.Count(&count).Error
	if err != nil {
		return err
	}

	if count == 0 {
		return errors.New("没有符合条件的敏感词记录")
	}

	// 执行删除
	err = query.Delete(&model.Sensitive{}).Error
	return err
}
