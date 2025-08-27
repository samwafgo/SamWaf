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

type WafCaServerInfoService struct{}

var WafCaServerInfoServiceApp = new(WafCaServerInfoService)

func (receiver *WafCaServerInfoService) AddApi(req request.WafCaServerInfoAddReq) error {
	var bean = &model.CaServerInfo{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},

		CaServerName:    req.CaServerName,
		CaServerAddress: req.CaServerAddress,
		Remarks:         req.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafCaServerInfoService) CheckIsExistApi(req request.WafCaServerInfoAddReq) int {
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.CaServerName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " ca_server_name=? "
	}

	//where字段赋值

	if len(req.CaServerName) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, req.CaServerName)
		}
	}

	global.GWAF_LOCAL_DB.Model(&model.CaServerInfo{}).Where(whereField, whereValues...).Count(&total)
	return int(total)
}

func (receiver *WafCaServerInfoService) ModifyApi(req request.WafCaServerInfoEditReq) error {
	// 根据唯一字段生成查询条件（只有在UniFields不为空时才进行存在性检查）

	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.CaServerName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " ca_server_name=? "
	}

	//where字段赋值

	if len(req.CaServerName) > 0 {
		whereValues = append(whereValues, req.CaServerName)
	}

	global.GWAF_LOCAL_DB.Model(&model.CaServerInfo{}).Where(whereField, whereValues...).Count(&total)
	// 查询是否已存在记录
	var bean model.CaServerInfo
	global.GWAF_LOCAL_DB.Model(&model.CaServerInfo{}).Where(whereField, whereValues...).Limit(1).Find(&bean)

	if int(total) > 0 && bean.Id != "" && bean.Id != req.Id {
		return errors.New("当前记录已经存在")
	}

	beanMap := map[string]interface{}{

		"CaServerName":    req.CaServerName,
		"CaServerAddress": req.CaServerAddress,
		"Remarks":         req.Remarks,

		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.CaServerInfo{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}
func (receiver *WafCaServerInfoService) GetDetailApi(req request.WafCaServerInfoDetailReq) model.CaServerInfo {
	var bean model.CaServerInfo
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafCaServerInfoService) GetDetailByIdApi(id string) model.CaServerInfo {
	var bean model.CaServerInfo
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafCaServerInfoService) GetListApi(req request.WafCaServerInfoSearchReq) ([]model.CaServerInfo, int64, error) {
	var list []model.CaServerInfo
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.CaServerInfo{}).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.CaServerInfo{}).Count(&total)

	return list, total, nil
}
func (receiver *WafCaServerInfoService) DelApi(req request.WafCaServerInfoDelReq) error {
	var bean model.CaServerInfo
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.CaServerInfo{}).Error
	return err
}
