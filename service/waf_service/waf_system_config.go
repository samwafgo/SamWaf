package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"errors"
	"fmt"
	"time"
)

type WafSystemConfigService struct{}

var WafSystemConfigServiceApp = new(WafSystemConfigService)

func (receiver *WafSystemConfigService) AddApi(wafSystemConfigAddReq request.WafSystemConfigAddReq) error {
	// 幂等保护：先检查 item 是否已存在，存在则跳过，防止重复插入
	var existing model.SystemConfig
	result := global.GWAF_LOCAL_DB.Where("item = ?", wafSystemConfigAddReq.Item).First(&existing)
	if result.Error == nil && existing.Id != "" {
		// 已存在，跳过插入
		return nil
	}
	var bean = &model.SystemConfig{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		ItemClass: wafSystemConfigAddReq.ItemClass,
		Item:      wafSystemConfigAddReq.Item,
		Value:     wafSystemConfigAddReq.Value,
		IsSystem:  "0",
		Remarks:   wafSystemConfigAddReq.Remarks,
		HashInfo:  "",
	}
	global.GWAF_LOCAL_DB.Create(bean)
	return nil
}

func (receiver *WafSystemConfigService) CheckIsExistApi(wafSystemConfigAddReq request.WafSystemConfigAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.SystemConfig{}, "item = ? ", wafSystemConfigAddReq.Item).Error
}
func (receiver *WafSystemConfigService) ModifyApi(req request.WafSystemConfigEditReq) error {
	var sysConfig model.SystemConfig
	global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Find(&sysConfig)
	if req.Id != "" && req.Item != req.Item {
		return errors.New("当前配置已经存在")
	}
	editMap := map[string]interface{}{
		"Item":        req.Item,
		"ItemClass":   req.ItemClass,
		"Value":       req.Value,
		"Remarks":     req.Remarks,
		"ItemType":    req.ItemType,
		"Options":     req.Options,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}

	err := global.GWAF_LOCAL_DB.Model(model.SystemConfig{}).Where("id = ?", req.Id).Updates(editMap).Error

	return err
}

// ModifyByItemApi 通过 item 修改系统配置的 value
func (receiver *WafSystemConfigService) ModifyByItemApi(req request.WafSystemConfigEditByItemReq) error {
	var sysConfig model.SystemConfig
	err := global.GWAF_LOCAL_DB.Where("item = ?", req.Item).First(&sysConfig).Error
	if err != nil {
		return errors.New("配置项不存在")
	}

	editMap := map[string]interface{}{
		"Value":       req.Value,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}

	err = global.GWAF_LOCAL_DB.Model(model.SystemConfig{}).Where("item = ?", req.Item).Updates(editMap).Error

	return err
}

func (receiver *WafSystemConfigService) GetDetailApi(req request.WafSystemConfigDetailReq) model.SystemConfig {
	var bean model.SystemConfig
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}
func (receiver *WafSystemConfigService) GetDetailByItemApi(req request.WafSystemConfigDetailByItemReq) model.SystemConfig {
	var bean model.SystemConfig
	global.GWAF_LOCAL_DB.Where("Item=?", req.Item).Find(&bean)
	return bean
}
func (receiver *WafSystemConfigService) GetDetailByIdApi(id string) model.SystemConfig {
	var bean model.SystemConfig
	global.GWAF_LOCAL_DB.Where("id=?", id).Find(&bean)
	return bean
}
func (receiver *WafSystemConfigService) GetDetailByItem(item string) model.SystemConfig {
	var bean model.SystemConfig
	global.GWAF_LOCAL_DB.Where("Item=?", item).Find(&bean)
	return bean
}
func (receiver *WafSystemConfigService) GetListApi(req request.WafSystemConfigSearchReq) ([]model.SystemConfig, int64, error) {
	var list []model.SystemConfig
	var total int64 = 0
	/*where条件*/
	var whereField = ""
	var whereValues []interface{}
	//where字段
	whereField = ""
	if len(req.Item) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " item=? "
	}
	if len(req.Remarks) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " remarks like ? "
	}
	//where字段赋值
	if len(req.Item) > 0 {
		whereValues = append(whereValues, req.Item)
	}
	if len(req.Remarks) > 0 {
		whereValues = append(whereValues, "%"+req.Remarks+"%")
	}
	global.GWAF_LOCAL_DB.Model(&model.SystemConfig{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.SystemConfig{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}
func (receiver *WafSystemConfigService) DelApi(req request.WafSystemConfigDelReq) error {
	var bean model.SystemConfig
	err := global.GWAF_LOCAL_DB.Where("id = ? and is_system=0", req.Id).First(&bean).Error
	if err != nil {
		return err
	}
	err = global.GWAF_LOCAL_DB.Where("id = ? and is_system=0", req.Id).Delete(model.SystemConfig{}).Error
	return err
}

// GetAllConfigs 批量获取所有配置项，返回以item为key的map
// 同时会对历史数据中同一 item 存在多条记录的情况进行预处理：保留最新一条，删除其余重复数据
func (receiver *WafSystemConfigService) GetAllConfigs() map[string]model.SystemConfig {
	var configs []model.SystemConfig
	configMap := make(map[string]model.SystemConfig)

	// 一次性查询所有配置
	global.GWAF_LOCAL_DB.Find(&configs)

	// 预处理：检测并清理同一 item 的重复记录（兼容历史版本脏数据）
	// 按 item 分组，如果同一 item 有多条记录，保留 UPDATE_TIME 最新的一条，删除其余
	itemGroup := make(map[string][]model.SystemConfig)
	for _, config := range configs {
		itemGroup[config.Item] = append(itemGroup[config.Item], config)
	}
	for item, group := range itemGroup {
		if len(group) <= 1 {
			continue
		}
		// 找出 UPDATE_TIME 最新的记录作为保留项
		keepIdx := 0
		for i := 1; i < len(group); i++ {
			if time.Time(group[i].UPDATE_TIME).After(time.Time(group[keepIdx].UPDATE_TIME)) {
				keepIdx = i
			}
		}
		// 收集需要删除的记录 ID（排除保留项，且仅删除有 Id 的记录）
		var deleteIds []string
		for i, g := range group {
			if i != keepIdx && g.Id != "" {
				deleteIds = append(deleteIds, g.Id)
			}
		}
		if len(deleteIds) > 0 {
			zlog.Warn(fmt.Sprintf(
				"[配置去重] item=%s 发现 %d 条重复记录，保留 id=%s (UPDATE_TIME=%s)，即将删除 %d 条: %v",
				item,
				len(group),
				group[keepIdx].Id,
				time.Time(group[keepIdx].UPDATE_TIME).Format("2006-01-02 15:04:05"),
				len(deleteIds),
				deleteIds,
			))
			global.GWAF_LOCAL_DB.Where("id IN ?", deleteIds).Delete(&model.SystemConfig{})
		}
		// 将保留项放入 map
		configMap[item] = group[keepIdx]
	}
	// 对于没有重复的 item，直接放入 map
	for _, config := range configs {
		if _, exists := configMap[config.Item]; !exists {
			configMap[config.Item] = config
		}
	}

	return configMap
}
