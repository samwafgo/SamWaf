package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/firewall"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"errors"
	"fmt"
	"time"
)

type WafFirewallIPBlockService struct {
	fw firewall.FireWallEngine
}

var WafFirewallIPBlockServiceApp = new(WafFirewallIPBlockService)

// AddApi 添加防火墙IP封禁（自动调用系统防火墙）
func (receiver *WafFirewallIPBlockService) AddApi(req request.WafFirewallIPBlockAddReq) error {
	// 1. 检查IP是否已存在
	var existBean model.FirewallIPBlock
	err := global.GWAF_LOCAL_DB.Where("ip = ? AND status = ?", req.IP, "active").First(&existBean).Error
	if err == nil && existBean.Id != "" {
		return errors.New("该IP已经被封禁")
	}

	// 2. 调用防火墙封禁IP
	err = receiver.fw.BlockIP(req.IP, req.Reason)
	if err != nil {
		return fmt.Errorf("防火墙封禁失败: %v", err)
	}

	// 3. 保存到数据库
	var bean = &model.FirewallIPBlock{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		HostCode:   req.HostCode,
		IP:         req.IP,
		Reason:     req.Reason,
		BlockType:  req.BlockType,
		Status:     "active",
		ExpireTime: req.ExpireTime,
		Remarks:    req.Remarks,
	}

	// 如果没有指定封禁类型，默认为手动封禁
	if bean.BlockType == "" {
		bean.BlockType = "manual"
	}

	err = global.GWAF_LOCAL_DB.Create(bean).Error
	if err != nil {
		// 如果数据库保存失败，回滚防火墙规则
		receiver.fw.UnblockIP(req.IP)
		return fmt.Errorf("保存到数据库失败: %v", err)
	}

	return nil
}

// CheckIsExistApi 检查IP是否已存在
func (receiver *WafFirewallIPBlockService) CheckIsExistApi(req request.WafFirewallIPBlockAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.FirewallIPBlock{}, "ip = ? AND status = ?", req.IP, "active").Error
}

// ModifyApi 修改防火墙IP封禁
func (receiver *WafFirewallIPBlockService) ModifyApi(req request.WafFirewallIPBlockEditReq) error {
	// 1. 获取原记录
	var oldBean model.FirewallIPBlock
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&oldBean).Error
	if err != nil {
		return errors.New("记录不存在")
	}

	// 2. 如果IP地址改变了，需要更新防火墙规则
	if oldBean.IP != req.IP {
		// 删除旧的防火墙规则
		if oldBean.Status == "active" {
			receiver.fw.UnblockIP(oldBean.IP)
		}

		// 添加新的防火墙规则
		err = receiver.fw.BlockIP(req.IP, req.Reason)
		if err != nil {
			// 如果新规则添加失败，恢复旧规则
			if oldBean.Status == "active" {
				receiver.fw.BlockIP(oldBean.IP, oldBean.Reason)
			}
			return fmt.Errorf("更新防火墙规则失败: %v", err)
		}
	}

	// 3. 更新数据库
	beanMap := map[string]interface{}{
		"HostCode":    req.HostCode,
		"IP":          req.IP,
		"Reason":      req.Reason,
		"BlockType":   req.BlockType,
		"Status":      req.Status,
		"ExpireTime":  req.ExpireTime,
		"Remarks":     req.Remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}

	err = global.GWAF_LOCAL_DB.Model(&model.FirewallIPBlock{}).Where("id = ?", req.Id).Updates(beanMap).Error
	if err != nil {
		// 如果数据库更新失败，回滚防火墙规则
		if oldBean.IP != req.IP {
			receiver.fw.UnblockIP(req.IP)
			if oldBean.Status == "active" {
				receiver.fw.BlockIP(oldBean.IP, oldBean.Reason)
			}
		}
		return fmt.Errorf("更新数据库失败: %v", err)
	}

	// 4. 如果状态改变，更新防火墙
	if oldBean.Status != req.Status {
		if req.Status == "active" {
			receiver.fw.BlockIP(req.IP, req.Reason)
		} else {
			receiver.fw.UnblockIP(req.IP)
		}
	}

	return nil
}

// GetDetailApi 获取防火墙IP封禁详情
func (receiver *WafFirewallIPBlockService) GetDetailApi(req request.WafFirewallIPBlockDetailReq) model.FirewallIPBlock {
	var bean model.FirewallIPBlock
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}

// GetDetailByIdApi 根据ID获取详情
func (receiver *WafFirewallIPBlockService) GetDetailByIdApi(id string) model.FirewallIPBlock {
	var bean model.FirewallIPBlock
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}

// GetListApi 获取防火墙IP封禁列表
func (receiver *WafFirewallIPBlockService) GetListApi(req request.WafFirewallIPBlockSearchReq) ([]model.FirewallIPBlock, int64, error) {
	var list []model.FirewallIPBlock
	var total int64 = 0

	// 构建查询条件
	query := global.GWAF_LOCAL_DB.Model(&model.FirewallIPBlock{})

	if len(req.HostCode) > 0 {
		query = query.Where("host_code = ?", req.HostCode)
	}
	if len(req.IP) > 0 {
		query = query.Where("ip LIKE ?", "%"+req.IP+"%")
	}
	if len(req.Reason) > 0 {
		query = query.Where("reason LIKE ?", "%"+req.Reason+"%")
	}
	if len(req.BlockType) > 0 {
		query = query.Where("block_type = ?", req.BlockType)
	}
	if len(req.Status) > 0 {
		query = query.Where("status = ?", req.Status)
	}

	// 统计总数
	query.Count(&total)

	// 分页查询
	err := query.Order("create_time DESC").
		Limit(req.PageSize).
		Offset(req.PageSize * (req.PageIndex - 1)).
		Find(&list).Error

	return list, total, err
}

// DelApi 删除防火墙IP封禁（同时删除系统防火墙规则）
func (receiver *WafFirewallIPBlockService) DelApi(req request.WafFirewallIPBlockDelReq) error {
	// 1. 获取记录
	var bean model.FirewallIPBlock
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return errors.New("记录不存在")
	}

	// 2. 删除防火墙规则
	if bean.Status == "active" {
		err = receiver.fw.UnblockIP(bean.IP)
		if err != nil {
			return fmt.Errorf("删除防火墙规则失败: %v", err)
		}
	}

	// 3. 删除数据库记录
	err = global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(&model.FirewallIPBlock{}).Error
	return err
}

// BatchDelApi 批量删除防火墙IP封禁
func (receiver *WafFirewallIPBlockService) BatchDelApi(req request.WafFirewallIPBlockBatchDelReq) error {
	if len(req.Ids) == 0 {
		return errors.New("删除ID列表不能为空")
	}

	// 1. 获取所有要删除的记录
	var beans []model.FirewallIPBlock
	err := global.GWAF_LOCAL_DB.Where("id IN ?", req.Ids).Find(&beans).Error
	if err != nil {
		return err
	}

	// 2. 批量删除防火墙规则
	var ipsToUnblock []string
	for _, bean := range beans {
		if bean.Status == "active" {
			ipsToUnblock = append(ipsToUnblock, bean.IP)
		}
	}

	if len(ipsToUnblock) > 0 {
		successCount, failedIPs, _ := receiver.fw.UnblockIPList(ipsToUnblock)
		if len(failedIPs) > 0 {
			return fmt.Errorf("部分IP解除封禁失败，成功%d个，失败%d个", successCount, len(failedIPs))
		}
	}

	// 3. 批量删除数据库记录
	err = global.GWAF_LOCAL_DB.Where("id IN ?", req.Ids).Delete(&model.FirewallIPBlock{}).Error
	return err
}

// BatchAddApi 批量添加防火墙IP封禁
func (receiver *WafFirewallIPBlockService) BatchAddApi(req request.WafFirewallIPBlockBatchAddReq) (successCount int, failedIPs []string, err error) {
	if len(req.IPs) == 0 {
		return 0, nil, errors.New("IP列表不能为空")
	}

	successCount = 0
	failedIPs = []string{}

	for _, ip := range req.IPs {
		addReq := request.WafFirewallIPBlockAddReq{
			HostCode:  req.HostCode,
			IP:        ip,
			Reason:    req.Reason,
			BlockType: req.BlockType,
			Remarks:   req.Remarks,
		}

		err := receiver.AddApi(addReq)
		if err != nil {
			failedIPs = append(failedIPs, ip)
		} else {
			successCount++
		}
	}

	if len(failedIPs) > 0 {
		return successCount, failedIPs, fmt.Errorf("部分IP封禁失败")
	}

	return successCount, failedIPs, nil
}

// EnableApi 启用防火墙IP封禁
func (receiver *WafFirewallIPBlockService) EnableApi(req request.WafFirewallIPBlockEnableReq) error {
	// 1. 获取记录
	var bean model.FirewallIPBlock
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return errors.New("记录不存在")
	}

	if bean.Status == "active" {
		return errors.New("该IP已经处于封禁状态")
	}

	// 2. 添加防火墙规则
	err = receiver.fw.BlockIP(bean.IP, bean.Reason)
	if err != nil {
		return fmt.Errorf("启用防火墙规则失败: %v", err)
	}

	// 3. 更新数据库状态
	err = global.GWAF_LOCAL_DB.Model(&model.FirewallIPBlock{}).
		Where("id = ?", req.Id).
		Updates(map[string]interface{}{
			"Status":      "active",
			"UPDATE_TIME": customtype.JsonTime(time.Now()),
		}).Error

	return err
}

// DisableApi 禁用防火墙IP封禁
func (receiver *WafFirewallIPBlockService) DisableApi(req request.WafFirewallIPBlockDisableReq) error {
	// 1. 获取记录
	var bean model.FirewallIPBlock
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return errors.New("记录不存在")
	}

	if bean.Status == "inactive" {
		return errors.New("该IP已经处于未封禁状态")
	}

	// 2. 删除防火墙规则
	err = receiver.fw.UnblockIP(bean.IP)
	if err != nil {
		return fmt.Errorf("禁用防火墙规则失败: %v", err)
	}

	// 3. 更新数据库状态
	err = global.GWAF_LOCAL_DB.Model(&model.FirewallIPBlock{}).
		Where("id = ?", req.Id).
		Updates(map[string]interface{}{
			"Status":      "inactive",
			"UPDATE_TIME": customtype.JsonTime(time.Now()),
		}).Error

	return err
}

// SyncFirewallRules 同步防火墙规则（从数据库恢复到系统防火墙）
func (receiver *WafFirewallIPBlockService) SyncFirewallRules(hostCode string) (successCount int, failedCount int, err error) {
	// 1. 获取所有active状态的记录
	var beans []model.FirewallIPBlock
	query := global.GWAF_LOCAL_DB.Where("status = ?", "active")

	if hostCode != "" {
		query = query.Where("host_code = ?", hostCode)
	}

	err = query.Find(&beans).Error
	if err != nil {
		return 0, 0, err
	}

	// 2. 批量添加到防火墙
	var ips []string
	for _, bean := range beans {
		ips = append(ips, bean.IP)
	}

	if len(ips) > 0 {
		successCount, failedIPs, _ := receiver.fw.BlockIPList(ips)
		failedCount = len(failedIPs)
		return successCount, failedCount, nil
	}

	return 0, 0, nil
}

// ClearExpiredRules 清理过期的封禁规则
func (receiver *WafFirewallIPBlockService) ClearExpiredRules() (int, error) {
	// 1. 查找所有过期的记录（ExpireTime > 0 且 < 当前时间）
	currentTime := time.Now().Unix()
	var beans []model.FirewallIPBlock
	err := global.GWAF_LOCAL_DB.Where("expire_time > 0 AND expire_time < ? AND status = ?", currentTime, "active").
		Find(&beans).Error
	if err != nil {
		return 0, err
	}

	count := 0
	for _, bean := range beans {
		// 删除防火墙规则
		err := receiver.fw.UnblockIP(bean.IP)
		if err == nil {
			// 更新数据库状态为inactive
			global.GWAF_LOCAL_DB.Model(&model.FirewallIPBlock{}).
				Where("id = ?", bean.Id).
				Updates(map[string]interface{}{
					"Status":      "inactive",
					"UPDATE_TIME": customtype.JsonTime(time.Now()),
				})
			count++
		}
	}

	return count, nil
}

// GetHostCodesByIds 根据ID列表获取对应的HostCode列表
func (receiver *WafFirewallIPBlockService) GetHostCodesByIds(ids []string) ([]string, error) {
	var hostCodes []string
	err := global.GWAF_LOCAL_DB.Model(&model.FirewallIPBlock{}).
		Where("id IN ?", ids).
		Distinct("host_code").
		Pluck("host_code", &hostCodes).Error
	return hostCodes, err
}

// GetAllActiveIPs 获取所有active状态的IP列表
func (receiver *WafFirewallIPBlockService) GetAllActiveIPs() ([]string, error) {
	var ips []string
	err := global.GWAF_LOCAL_DB.Model(&model.FirewallIPBlock{}).
		Where("status = ?", "active").
		Pluck("ip", &ips).Error
	return ips, err
}

// GetStatistics 获取统计信息
func (receiver *WafFirewallIPBlockService) GetStatistics() map[string]interface{} {
	var total, active, inactive, expired int64

	global.GWAF_LOCAL_DB.Model(&model.FirewallIPBlock{}).Count(&total)
	global.GWAF_LOCAL_DB.Model(&model.FirewallIPBlock{}).Where("status = ?", "active").Count(&active)
	global.GWAF_LOCAL_DB.Model(&model.FirewallIPBlock{}).Where("status = ?", "inactive").Count(&inactive)

	currentTime := time.Now().Unix()
	global.GWAF_LOCAL_DB.Model(&model.FirewallIPBlock{}).
		Where("expire_time > 0 AND expire_time < ?", currentTime).Count(&expired)

	return map[string]interface{}{
		"total":    total,
		"active":   active,
		"inactive": inactive,
		"expired":  expired,
	}
}
