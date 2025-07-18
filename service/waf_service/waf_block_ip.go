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

type WafBlockIpService struct{}

var WafBlockIpServiceApp = new(WafBlockIpService)

func (receiver *WafBlockIpService) AddApi(req request.WafBlockIpAddReq) error {
	var bean = &model.IPBlockList{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode: req.HostCode,
		Ip:       req.Ip,
		Remarks:  req.Remarks,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafBlockIpService) CheckIsExistApi(req request.WafBlockIpAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.IPBlockList{}, "host_code = ? and ip= ?", req.HostCode,
		req.Ip).Error
}
func (receiver *WafBlockIpService) ModifyApi(req request.WafBlockIpEditReq) error {
	var ipWhite model.IPBlockList
	global.GWAF_LOCAL_DB.Where("host_code = ? and ip= ?", req.HostCode,
		req.Ip).Find(&ipWhite)
	if ipWhite.Id != "" && ipWhite.Ip != req.Ip {
		return errors.New("当前网站和IP已经存在")
	}
	ipWhiteMap := map[string]interface{}{
		"Host_Code":   req.HostCode,
		"Ip":          req.Ip,
		"Remarks":     req.Remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	err := global.GWAF_LOCAL_DB.Model(model.IPBlockList{}).Where("id = ?", req.Id).Updates(ipWhiteMap).Error

	return err
}
func (receiver *WafBlockIpService) GetDetailApi(req request.WafBlockIpDetailReq) model.IPBlockList {
	var bean model.IPBlockList
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafBlockIpService) GetDetailByIdApi(id string) model.IPBlockList {
	var bean model.IPBlockList
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafBlockIpService) GetDetailByIPApi(ip string, hostCode string) model.IPBlockList {
	var ipBlocks model.IPBlockList
	global.GWAF_LOCAL_DB.Where("ip=? and host_code=?", ip, hostCode).Find(&ipBlocks)
	return ipBlocks
}
func (receiver *WafBlockIpService) GetListApi(req request.WafBlockIpSearchReq) ([]model.IPBlockList, int64, error) {
	var list []model.IPBlockList
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
	if len(req.Ip) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " ip =? "
	}
	//where字段赋值
	if len(req.HostCode) > 0 {
		whereValues = append(whereValues, req.HostCode)
	}
	if len(req.Ip) > 0 {
		whereValues = append(whereValues, req.Ip)
	}

	global.GWAF_LOCAL_DB.Model(&model.IPBlockList{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.IPBlockList{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafBlockIpService) DelApi(req request.WafBlockIpDelReq) error {
	var bean model.IPBlockList
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(model.IPBlockList{}).Error
	return err
}

// BatchDelApi 批量删除指定ID的IP黑名单
func (receiver *WafBlockIpService) BatchDelApi(req request.WafBlockIpBatchDelReq) error {
	if len(req.Ids) == 0 {
		return errors.New("删除ID列表不能为空")
	}

	// 先检查所有ID是否存在
	var count int64
	err := global.GWAF_LOCAL_DB.Model(&model.IPBlockList{}).Where("id IN ?", req.Ids).Count(&count).Error
	if err != nil {
		return err
	}

	if count != int64(len(req.Ids)) {
		return errors.New("部分ID不存在")
	}

	// 执行批量删除
	err = global.GWAF_LOCAL_DB.Where("id IN ?", req.Ids).Delete(&model.IPBlockList{}).Error
	return err
}

// DelAllApi 删除指定网站的所有IP黑名单
func (receiver *WafBlockIpService) DelAllApi(req request.WafBlockIpDelAllReq) error {
	// 先检查是否存在记录
	var count int64
	err := global.GWAF_LOCAL_DB.Model(&model.IPBlockList{}).Count(&count).Error
	if err != nil {
		return err
	}

	if count == 0 {
		return errors.New("没有IP黑名单记录")
	}

	// 执行全量删除 - 限制在当前租户和用户范围内
	err = global.GWAF_LOCAL_DB.
		Where("user_code = ? AND tenant_id = ?", global.GWAF_USER_CODE, global.GWAF_TENANT_ID).
		Delete(&model.IPBlockList{}).Error
	return err
}

// GetHostCodesByIds 根据ID列表获取对应的HostCode列表（用于通知WAF引擎）
func (receiver *WafBlockIpService) GetHostCodesByIds(ids []string) ([]string, error) {
	var hostCodes []string
	err := global.GWAF_LOCAL_DB.Model(&model.IPBlockList{}).
		Where("id IN ?", ids).
		Distinct("host_code").
		Pluck("host_code", &hostCodes).Error
	return hostCodes, err
}

// GetHostCodes 获取所有HostCode列表（用于通知WAF引擎）
func (receiver *WafBlockIpService) GetHostCodes() ([]string, error) {
	var hostCodes []string
	err := global.GWAF_LOCAL_DB.Model(&model.IPBlockList{}).
		Distinct("host_code").
		Where("user_code = ? AND tenant_id = ?", global.GWAF_USER_CODE, global.GWAF_TENANT_ID).
		Pluck("host_code", &hostCodes).Error
	return hostCodes, err
}
