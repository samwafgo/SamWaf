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

type WafHttpAuthBaseService struct{}

var WafHttpAuthBaseServiceApp = new(WafHttpAuthBaseService)

func (receiver *WafHttpAuthBaseService) AddApi(req request.WafHttpAuthBaseAddReq) error {
	var bean = &model.HttpAuthBase{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},

		HostCode: req.HostCode,
		UserName: req.UserName,
		Password: req.Password,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafHttpAuthBaseService) CheckIsExistApi(req request.WafHttpAuthBaseAddReq) int {
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " host_code=? "
	}

	if len(req.UserName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " user_name=? "
	}

	//where字段赋值

	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, req.HostCode)
		}
	}

	if len(req.UserName) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, req.UserName)
		}
	}

	global.GWAF_LOCAL_DB.Model(&model.HttpAuthBase{}).Where(whereField, whereValues...).Count(&total)
	return int(total)
}

func (receiver *WafHttpAuthBaseService) ModifyApi(req request.WafHttpAuthBaseEditReq) error {
	// 根据唯一字段生成查询条件（只有在UniFields不为空时才进行存在性检查）
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " host_code=? "
	}

	if len(req.UserName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " user_name=? "
	}

	//where字段赋值

	if len(req.HostCode) > 0 {
		whereValues = append(whereValues, req.HostCode)
	}

	if len(req.UserName) > 0 {
		whereValues = append(whereValues, req.UserName)
	}

	global.GWAF_LOCAL_DB.Model(&model.HttpAuthBase{}).Where(whereField, whereValues...).Count(&total)
	// 查询是否已存在记录
	var bean model.HttpAuthBase
	global.GWAF_LOCAL_DB.Model(&model.HttpAuthBase{}).Where(whereField, whereValues...).Limit(1).Find(&bean)

	if int(total) > 0 && bean.Id != "" && bean.Id != req.Id {
		return errors.New("当前记录已经存在")
	}

	beanMap := map[string]interface{}{
		"HostCode":    req.HostCode,
		"UserName":    req.UserName,
		"Password":    req.Password,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.HttpAuthBase{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}
func (receiver *WafHttpAuthBaseService) GetDetailApi(req request.WafHttpAuthBaseDetailReq) model.HttpAuthBase {
	var bean model.HttpAuthBase
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafHttpAuthBaseService) GetDetailByIdApi(id string) model.HttpAuthBase {
	var bean model.HttpAuthBase
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafHttpAuthBaseService) GetListApi(req request.WafHttpAuthBaseSearchReq) ([]model.HttpAuthBase, int64, error) {
	var list []model.HttpAuthBase
	var total int64 = 0

	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""
	if len(req.HostCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " host_code=? "
	}
	if len(req.UserName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " user_name =? "
	}
	//where字段赋值
	if len(req.HostCode) > 0 {
		whereValues = append(whereValues, req.HostCode)
	}
	if len(req.UserName) > 0 {
		whereValues = append(whereValues, req.UserName)
	}

	global.GWAF_LOCAL_DB.Model(&model.HttpAuthBase{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.HttpAuthBase{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafHttpAuthBaseService) DelApi(req request.WafHttpAuthBaseDelReq) error {
	var bean model.HttpAuthBase
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.HttpAuthBase{}).Error
	return err
}
