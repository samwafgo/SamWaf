package waf_service

import (
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/request"
	"fmt"
	"time"
)

type WafDataRetentionService struct{}

var WafDataRetentionServiceApp = new(WafDataRetentionService)

// GetAllPolicies 获取所有数据保留策略
func (s *WafDataRetentionService) GetAllPolicies() ([]model.DataRetentionPolicy, error) {
	var policies []model.DataRetentionPolicy
	err := global.GWAF_LOCAL_DB.Find(&policies).Error
	return policies, err
}

// GetPolicyByTable 按表名获取策略
func (s *WafDataRetentionService) GetPolicyByTable(tableName string) (*model.DataRetentionPolicy, error) {
	var policy model.DataRetentionPolicy
	err := global.GWAF_LOCAL_DB.Where("table_name = ?", tableName).First(&policy).Error
	if err != nil {
		return nil, fmt.Errorf("策略不存在: %w", err)
	}
	return &policy, nil
}

// UpdatePolicy 更新策略（只允许修改业务字段，不允许修改 table_name）
func (s *WafDataRetentionService) UpdatePolicy(policy *model.DataRetentionPolicy) error {
	now := customtype.JsonTime(time.Now())
	return global.GWAF_LOCAL_DB.Model(policy).Updates(map[string]interface{}{
		"retain_days":     policy.RetainDays,
		"retain_rows":     policy.RetainRows,
		"day_field":       policy.DayField,
		"day_field_type":  policy.DayFieldType,
		"row_order_field": policy.RowOrderField,
		"row_order_dir":   policy.RowOrderDir,
		"clean_enabled":   policy.CleanEnabled,
		"remarks":         policy.Remarks,
		"update_time":     now,
	}).Error
}

// GetPolicyById 按 ID 获取策略
func (s *WafDataRetentionService) GetPolicyById(id string) (*model.DataRetentionPolicy, error) {
	var policy model.DataRetentionPolicy
	err := global.GWAF_LOCAL_DB.Where("id = ?", id).First(&policy).Error
	if err != nil {
		return nil, fmt.Errorf("策略不存在: %w", err)
	}
	return &policy, nil
}

// UpdatePolicyById 按 ID 更新策略（仅允许修改业务字段）
func (s *WafDataRetentionService) UpdatePolicyById(req request.WafDataRetentionEditReq) error {
	now := customtype.JsonTime(time.Now())
	return global.GWAF_LOCAL_DB.Model(&model.DataRetentionPolicy{}).
		Where("id = ?", req.Id).
		Updates(map[string]interface{}{
			"retain_days":   req.RetainDays,
			"retain_rows":   req.RetainRows,
			"clean_enabled": req.CleanEnabled,
			"remarks":       req.Remarks,
			"update_time":   now,
		}).Error
}

// EnablePolicy 启用策略
func (s *WafDataRetentionService) EnablePolicy(id string) error {
	now := customtype.JsonTime(time.Now())
	return global.GWAF_LOCAL_DB.Model(&model.DataRetentionPolicy{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"clean_enabled": 1,
			"update_time":   now,
		}).Error
}

// DisablePolicy 禁用策略
func (s *WafDataRetentionService) DisablePolicy(id string) error {
	now := customtype.JsonTime(time.Now())
	return global.GWAF_LOCAL_DB.Model(&model.DataRetentionPolicy{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"clean_enabled": 0,
			"update_time":   now,
		}).Error
}
