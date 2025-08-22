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

type WafBlockUrlService struct{}

var WafBlockUrlServiceApp = new(WafBlockUrlService)

func (receiver *WafBlockUrlService) AddApi(req request.WafBlockUrlAddReq) error {
	var bean = &model.URLBlockList{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode:    req.HostCode,
		Url:         req.Url,
		CompareType: req.CompareType,
		Remarks:     req.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafBlockUrlService) CheckIsExistApi(req request.WafBlockUrlAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.URLBlockList{}, "host_code = ? and url= ?", req.HostCode,
		req.Url).Error
}
func (receiver *WafBlockUrlService) ModifyApi(req request.WafBlockUrlEditReq) error {
	var bean model.URLBlockList
	global.GWAF_LOCAL_DB.Where("host_code = ? and url= ?", req.HostCode,
		req.Url).Find(&bean)
	if bean.Id != "" && bean.Url != req.Url {
		return errors.New("当前网站和url已经存在")
	}
	modfiyMap := map[string]interface{}{
		"Host_Code":   req.HostCode,
		"Url":         req.Url,
		"Remarks":     req.Remarks,
		"CompareType": req.CompareType,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.URLBlockList{}).Where("id = ?", req.Id).Updates(modfiyMap).Error

	return err
}
func (receiver *WafBlockUrlService) GetDetailApi(req request.WafBlockUrlDetailReq) model.URLBlockList {
	var bean model.URLBlockList
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafBlockUrlService) GetDetailByIdApi(id string) model.URLBlockList {
	var bean model.URLBlockList
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafBlockUrlService) GetListApi(req request.WafBlockUrlSearchReq) ([]model.URLBlockList, int64, error) {
	var list []model.URLBlockList
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
	if len(req.Url) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " url =? "
	}
	//where字段赋值
	if len(req.HostCode) > 0 {
		whereValues = append(whereValues, req.HostCode)
	}
	if len(req.Url) > 0 {
		whereValues = append(whereValues, req.Url)
	}

	global.GWAF_LOCAL_DB.Model(&model.URLBlockList{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.URLBlockList{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafBlockUrlService) DelApi(req request.WafBlockUrlDelReq) error {
	var bean model.URLBlockList
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.URLBlockList{}).Error
	return err
}

// BatchDelApi 批量删除指定ID的URL黑名单
func (receiver *WafBlockUrlService) BatchDelApi(req request.WafBlockUrlBatchDelReq) error {
	if len(req.Ids) == 0 {
		return errors.New("删除ID列表不能为空")
	}

	// 先检查所有ID是否存在
	var count int64
	err := global.GWAF_LOCAL_DB.Model(&model.URLBlockList{}).Where("id IN ? AND user_code = ? AND tenant_id = ?", req.Ids, global.GWAF_USER_CODE, global.GWAF_TENANT_ID).Count(&count).Error
	if err != nil {
		return err
	}

	if count != int64(len(req.Ids)) {
		return errors.New("部分ID不存在")
	}

	// 执行批量删除
	err = global.GWAF_LOCAL_DB.Where("id IN ? AND user_code = ? AND tenant_id = ?", req.Ids, global.GWAF_USER_CODE, global.GWAF_TENANT_ID).Delete(&model.URLBlockList{}).Error
	return err
}

// DelAllApi 删除指定网站的所有URL黑名单
func (receiver *WafBlockUrlService) DelAllApi(req request.WafBlockUrlDelAllReq) error {
	var whereCondition string
	var whereValues []interface{}

	if len(req.HostCode) > 0 {
		whereCondition = "host_code = ? AND user_code = ? AND tenant_id = ?"
		whereValues = append(whereValues, req.HostCode, global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
	} else {
		whereCondition = "user_code = ? AND tenant_id = ?"
		whereValues = append(whereValues, global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
	}

	// 先检查是否存在记录
	var count int64
	err := global.GWAF_LOCAL_DB.Model(&model.URLBlockList{}).Where(whereCondition, whereValues...).Count(&count).Error
	if err != nil {
		return err
	}

	if count == 0 {
		return errors.New("没有URL黑名单记录")
	}

	// 执行删除
	err = global.GWAF_LOCAL_DB.Where(whereCondition, whereValues...).Delete(&model.URLBlockList{}).Error
	return err
}

// GetHostCodesByIds 根据ID数组获取对应的HostCode列表
func (receiver *WafBlockUrlService) GetHostCodesByIds(ids []string) ([]string, error) {
	var hostCodes []string
	err := global.GWAF_LOCAL_DB.Model(&model.URLBlockList{}).Where("id IN ?", ids).Distinct("host_code").Pluck("host_code", &hostCodes).Error
	return hostCodes, err
}

// GetHostCodes 获取所有HostCode列表
func (receiver *WafBlockUrlService) GetHostCodes() ([]string, error) {
	var hostCodes []string
	err := global.GWAF_LOCAL_DB.Model(&model.URLBlockList{}).Where("user_code = ? AND tenant_id = ?", global.GWAF_USER_CODE, global.GWAF_TENANT_ID).Distinct("host_code").Pluck("host_code", &hostCodes).Error
	return hostCodes, err
}
