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

type WafWhiteUrlService struct{}

var WafWhiteUrlServiceApp = new(WafWhiteUrlService)

func (receiver *WafWhiteUrlService) AddApi(req request.WafAllowUrlAddReq) error {
	var bean = &model.URLAllowList{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode:    req.HostCode,
		CompareType: req.CompareType,
		Url:         req.Url,
		Remarks:     req.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafWhiteUrlService) CheckIsExistApi(req request.WafAllowUrlAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.URLAllowList{}, "host_code = ? and url= ?", req.HostCode,
		req.Url).Error
}
func (receiver *WafWhiteUrlService) ModifyApi(req request.WafAllowUrlEditReq) error {
	var ipWhite model.URLAllowList
	global.GWAF_LOCAL_DB.Where("host_code = ? and url= ?", req.HostCode,
		req.Url).Find(&ipWhite)
	if ipWhite.Id != "" && ipWhite.Url != req.Url {
		return errors.New("当前网站和url已经存在")
	}
	ipWhiteMap := map[string]interface{}{
		"Host_Code":    req.HostCode,
		"Compare_Type": req.CompareType,
		"Url":          req.Url,
		"Remarks":      req.Remarks,
		"UPDATE_TIME":  customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.URLAllowList{}).Where("id = ?", req.Id).Updates(ipWhiteMap).Error

	return err
}
func (receiver *WafWhiteUrlService) GetDetailApi(req request.WafAllowUrlDetailReq) model.URLAllowList {
	var bean model.URLAllowList
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafWhiteUrlService) GetDetailByIdApi(id string) model.URLAllowList {
	var bean model.URLAllowList
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafWhiteUrlService) GetListApi(req request.WafAllowUrlSearchReq) ([]model.URLAllowList, int64, error) {
	var list []model.URLAllowList
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

	global.GWAF_LOCAL_DB.Model(&model.URLAllowList{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.URLAllowList{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafWhiteUrlService) DelApi(req request.WafAllowUrlDelReq) error {
	var ipWhite model.URLAllowList
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&ipWhite).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.URLAllowList{}).Error
	return err
}

// 批量删除方法
func (receiver *WafWhiteUrlService) BatchDelApi(req request.WafAllowUrlBatchDelReq) error {
	// 添加用户和租户验证
	err := global.GWAF_LOCAL_DB.Where("id IN ? AND user_code = ? AND tenant_id = ?", req.Ids, global.GWAF_USER_CODE, global.GWAF_TENANT_ID).Delete(&model.URLAllowList{}).Error
	return err
}

// 全部删除方法
func (receiver *WafWhiteUrlService) DelAllApi(req request.WafAllowUrlDelAllReq) error {
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
	err := global.GWAF_LOCAL_DB.Model(&model.URLAllowList{}).Where(whereCondition, whereValues...).Count(&count).Error
	if err != nil {
		return err
	}

	if count == 0 {
		return errors.New("没有URL白名单记录")
	}

	// 执行删除
	err = global.GWAF_LOCAL_DB.Where(whereCondition, whereValues...).Delete(&model.URLAllowList{}).Error
	return err
}

// GetHostCodesByIds 根据ID数组获取对应的HostCode列表
func (receiver *WafWhiteUrlService) GetHostCodesByIds(ids []string) ([]string, error) {
	var hostCodes []string
	err := global.GWAF_LOCAL_DB.Model(&model.URLAllowList{}).Where("id IN ?", ids).Distinct("host_code").Pluck("host_code", &hostCodes).Error
	return hostCodes, err
}

// GetHostCodes 获取所有HostCode列表
func (receiver *WafWhiteUrlService) GetHostCodes() ([]string, error) {
	var hostCodes []string
	err := global.GWAF_LOCAL_DB.Model(&model.URLAllowList{}).Where("user_code = ? AND tenant_id = ?", global.GWAF_USER_CODE, global.GWAF_TENANT_ID).Distinct("host_code").Pluck("host_code", &hostCodes).Error
	return hostCodes, err
}
