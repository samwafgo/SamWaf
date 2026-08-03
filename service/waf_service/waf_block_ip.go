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
		HostCode:  req.HostCode,
		Ip:        req.Ip,
		Remarks:   req.Remarks,
		IpType:    req.IpType,
		GroupCode: req.GroupCode,
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

// CheckIsExistApi 判重。唯一性由 (host_code, ip_type, ip, group_code) 共同决定：
// 同一站点重复引用同一个 IP 组也算重复。
// ip_type 用 IN ('', 'ip') 兼容存量行的空串。
func (receiver *WafBlockIpService) CheckIsExistApi(req request.WafBlockIpAddReq) error {
	if req.IpType == model.IPEntryTypeGroup {
		return global.GWAF_LOCAL_DB.First(&model.IPBlockList{},
			"host_code = ? and ip_type = ? and group_code = ?", req.HostCode, model.IPEntryTypeGroup, req.GroupCode).Error
	}
	return global.GWAF_LOCAL_DB.First(&model.IPBlockList{},
		"host_code = ? and ip = ? and (ip_type is null or ip_type in (?, ?))",
		req.HostCode, req.Ip, "", model.IPEntryTypeIP).Error
}
func (receiver *WafBlockIpService) ModifyApi(req request.WafBlockIpEditReq) error {
	// 同一站点下不能出现重复条目（排除自身）
	var dup model.IPBlockList
	if req.IpType == model.IPEntryTypeGroup {
		global.GWAF_LOCAL_DB.Where("host_code = ? and ip_type = ? and group_code = ? and id <> ?",
			req.HostCode, model.IPEntryTypeGroup, req.GroupCode, req.Id).Find(&dup)
	} else {
		global.GWAF_LOCAL_DB.Where("host_code = ? and ip = ? and (ip_type is null or ip_type in (?, ?)) and id <> ?",
			req.HostCode, req.Ip, "", model.IPEntryTypeIP, req.Id).Find(&dup)
	}
	if dup.Id != "" {
		return errors.New("当前网站和IP已经存在")
	}
	ipWhiteMap := map[string]interface{}{
		"host_code":   req.HostCode,
		"Ip":          req.Ip,
		"Remarks":     req.Remarks,
		"ip_type":     req.IpType,
		"group_code":  req.GroupCode,
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
	//按引用的IP组筛选：ip 是精确匹配，组引用行的 ip 为空，用 ip 条件永远查不到
	if len(req.GroupCode) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " group_code =? "
	}
	//where字段赋值
	if len(req.HostCode) > 0 {
		whereValues = append(whereValues, req.HostCode)
	}
	if len(req.Ip) > 0 {
		whereValues = append(whereValues, req.Ip)
	}
	if len(req.GroupCode) > 0 {
		whereValues = append(whereValues, req.GroupCode)
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
	var whereCondition string
	var whereValues []interface{}

	// 指定了网站就只清空该网站，为空才是清空全部（原先无条件删全部，会误删其它网站的黑名单）
	if len(req.HostCode) > 0 {
		whereCondition = "host_code = ? AND user_code = ? AND tenant_id = ?"
		whereValues = append(whereValues, req.HostCode, global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
	} else {
		whereCondition = "user_code = ? AND tenant_id = ?"
		whereValues = append(whereValues, global.GWAF_USER_CODE, global.GWAF_TENANT_ID)
	}

	// 先检查是否存在记录
	var count int64
	err := global.GWAF_LOCAL_DB.Model(&model.IPBlockList{}).Where(whereCondition, whereValues...).Count(&count).Error
	if err != nil {
		return err
	}

	if count == 0 {
		return errors.New("没有IP黑名单记录")
	}

	// 执行删除 - 限制在当前租户和用户范围内
	err = global.GWAF_LOCAL_DB.
		Where(whereCondition, whereValues...).
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

// GetAllBlockIpApi 获取所有IP黑名单数据（用于导出）
func (receiver *WafBlockIpService) GetAllBlockIpApi() []model.IPBlockList {
	var list []model.IPBlockList
	global.GWAF_LOCAL_DB.Where("user_code = ? AND tenant_id = ?", global.GWAF_USER_CODE, global.GWAF_TENANT_ID).Find(&list)
	return list
}
