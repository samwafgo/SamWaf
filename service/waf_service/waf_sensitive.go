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

type WafSensitiveService struct{}

var WafSensitiveServiceApp = new(WafSensitiveService)

func (receiver *WafSensitiveService) AddApi(req request.WafSensitiveAddReq) error {
	var bean = &model.Sensitive{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.NewV4().String(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		Type:    req.Type,
		Content: req.Content,
		Remarks: req.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafSensitiveService) CheckIsExistApi(req request.WafSensitiveAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.Sensitive{}, "type = ? and content= ?", req.Type,
		req.Content).Error
}
func (receiver *WafSensitiveService) ModifyApi(req request.WafSensitiveEditReq) error {
	var bean model.Sensitive
	global.GWAF_LOCAL_DB.Where("type = ? and content= ?", req.Type,
		req.Content).Find(&bean)
	if bean.Id != "" && bean.Type != req.Type && bean.Content != req.Content {
		return errors.New("当前敏感词已经存在")
	}
	beanMap := map[string]interface{}{
		"Type":        req.Type,
		"Content":     req.Content,
		"Remarks":     req.Remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
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
	if req.Type > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " type =? "
	}
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
	if req.Type > 0 {
		whereValues = append(whereValues, req.Type)
	}
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
