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

type WafPrivateGroupService struct{}

var WafPrivateGroupServiceApp = new(WafPrivateGroupService)

func (receiver *WafPrivateGroupService) AddApi(req request.WafPrivateGroupAddReq) error {
	var bean = &model.PrivateGroup{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},

		PrivateGroupName:        req.PrivateGroupName,
		PrivateGroupBelongCloud: req.PrivateGroupBelongCloud,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafPrivateGroupService) CheckIsExistApi(req request.WafPrivateGroupAddReq) int {
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.PrivateGroupName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " private_group_name=? "
	}

	if len(req.PrivateGroupBelongCloud) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " private_group_belong_cloud=? "
	}

	//where字段赋值

	if len(req.PrivateGroupName) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, req.PrivateGroupName)
		}
	}

	if len(req.PrivateGroupBelongCloud) > 0 {
		if len(whereField) > 0 {
			whereValues = append(whereValues, req.PrivateGroupBelongCloud)
		}
	}

	global.GWAF_LOCAL_DB.Model(&model.PrivateGroup{}).Where(whereField, whereValues...).Count(&total)
	return int(total)
}

func (receiver *WafPrivateGroupService) ModifyApi(req request.WafPrivateGroupEditReq) error {
	// 根据唯一字段生成查询条件（只有在UniFields不为空时才进行存在性检查）

	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	if len(req.PrivateGroupName) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " private_group_name=? "
	}

	if len(req.PrivateGroupBelongCloud) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " private_group_belong_cloud=? "
	}

	//where字段赋值

	if len(req.PrivateGroupName) > 0 {
		whereValues = append(whereValues, req.PrivateGroupName)
	}

	if len(req.PrivateGroupBelongCloud) > 0 {
		whereValues = append(whereValues, req.PrivateGroupBelongCloud)
	}

	global.GWAF_LOCAL_DB.Model(&model.PrivateGroup{}).Where(whereField, whereValues...).Count(&total)
	// 查询是否已存在记录
	var bean model.PrivateGroup
	global.GWAF_LOCAL_DB.Model(&model.PrivateGroup{}).Where(whereField, whereValues...).Limit(1).Find(&bean)

	if int(total) > 0 && bean.Id != "" && bean.Id != req.Id {
		return errors.New("当前记录已经存在")
	}

	beanMap := map[string]interface{}{
		"PrivateGroupName":        req.PrivateGroupName,
		"PrivateGroupBelongCloud": req.PrivateGroupBelongCloud,
		"UPDATE_TIME":             customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.PrivateGroup{}).Where("id = ?", req.Id).Updates(beanMap).Error

	return err
}
func (receiver *WafPrivateGroupService) GetDetailApi(req request.WafPrivateGroupDetailReq) model.PrivateGroup {
	var bean model.PrivateGroup
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafPrivateGroupService) GetDetailByIdApi(id string) model.PrivateGroup {
	var bean model.PrivateGroup
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafPrivateGroupService) GetListApi(req request.WafPrivateGroupSearchReq) ([]model.PrivateGroup, int64, error) {
	var list []model.PrivateGroup
	var total int64 = 0
	global.GWAF_LOCAL_DB.Model(&model.PrivateGroup{}).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.PrivateGroup{}).Count(&total)

	return list, total, nil
}
func (receiver *WafPrivateGroupService) GetListByBelongCloudApi(req request.WafPrivateGroupSearchByCloudReq) ([]model.PrivateGroup, int64, error) {
	var list []model.PrivateGroup
	var total int64 = 0

	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""

	whereField = whereField + " private_group_belong_cloud=? "

	//where字段赋值
	if len(req.PrivateGroupBelongCloud) > 0 {
		whereValues = append(whereValues, req.PrivateGroupBelongCloud)
	} else {
		whereValues = append(whereValues, "samwaf-not-exist")
	}

	global.GWAF_LOCAL_DB.Model(&model.PrivateGroup{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.PrivateGroup{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafPrivateGroupService) DelApi(req request.WafPrivateGroupDelReq) error {
	var bean model.PrivateGroup
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.PrivateGroup{}).Error
	return err
}
