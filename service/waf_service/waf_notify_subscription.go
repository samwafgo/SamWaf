package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafdb/dialect"
	"time"
)

type WafNotifySubscriptionService struct{}

var WafNotifySubscriptionServiceApp = new(WafNotifySubscriptionService)

// AddApi 添加通知订阅
func (receiver *WafNotifySubscriptionService) AddApi(req request.WafNotifySubscriptionAddReq) error {
	var bean = &model.NotifySubscription{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		ChannelId:   req.ChannelId,
		MessageType: req.MessageType,
		Recipients:  req.Recipients,
		Status:      req.Status,
		FilterJSON:  req.FilterJSON,
		Remarks:     req.Remarks,
	}
	return global.GWAF_LOCAL_DB.Create(bean).Error
}

// CheckIsExistApi 检查是否存在
func (receiver *WafNotifySubscriptionService) CheckIsExistApi(req request.WafNotifySubscriptionAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.NotifySubscription{}, "channel_id = ? and message_type = ? ", req.ChannelId, req.MessageType).Error
}

// ModifyApi 修改通知订阅
func (receiver *WafNotifySubscriptionService) ModifyApi(req request.WafNotifySubscriptionEditReq) error {
	editMap := map[string]interface{}{
		"ChannelId":   req.ChannelId,
		"MessageType": req.MessageType,
		"Recipients":  req.Recipients,
		"Status":      req.Status,
		"FilterJSON":  req.FilterJSON,
		"Remarks":     req.Remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	return global.GWAF_LOCAL_DB.Model(model.NotifySubscription{}).Where("id = ?", req.Id).Updates(editMap).Error
}

// GetDetailApi 获取详情
func (receiver *WafNotifySubscriptionService) GetDetailApi(req request.WafNotifySubscriptionDetailReq) model.NotifySubscription {
	var bean model.NotifySubscription
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}

// GetListApi 获取列表
func (receiver *WafNotifySubscriptionService) GetListApi(req request.WafNotifySubscriptionSearchReq) ([]model.NotifySubscription, int64, error) {
	var list []model.NotifySubscription
	var total int64 = 0

	var whereField = ""
	var whereValues []interface{}

	if len(req.ChannelId) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " channel_id = ? "
		whereValues = append(whereValues, req.ChannelId)
	}

	if len(req.MessageType) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " message_type = ? "
		whereValues = append(whereValues, req.MessageType)
	}

	if req.Status > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " status = ? "
		whereValues = append(whereValues, req.Status)
	}

	global.GWAF_LOCAL_DB.Model(&model.NotifySubscription{}).Where(whereField, whereValues...).Limit(req.PageSize).Order("create_time desc").Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.NotifySubscription{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}

// DelApi 删除
func (receiver *WafNotifySubscriptionService) DelApi(req request.WafNotifySubscriptionDelReq) error {
	return global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(&model.NotifySubscription{}).Error
}

// GetById 按主键取订阅
func (receiver *WafNotifySubscriptionService) GetById(id string) (model.NotifySubscription, error) {
	var bean model.NotifySubscription
	err := global.GWAF_LOCAL_DB.Where("id = ?", id).First(&bean).Error
	return bean, err
}

// SaveConfigApi 保存单个订阅的精细化配置（频控/模板/过滤）
//
// 刻意与 ModifyApi 分开：ModifyApi 会被前端的开关切换整包提交，
// 合在一起的话漏传一个字段就会把用户配好的模板清空。
func (receiver *WafNotifySubscriptionService) SaveConfigApi(id, throttleMode, throttleJSON, filterJSON,
	titleTemplate, contentTemplate string) error {
	editMap := map[string]interface{}{
		"ThrottleMode":    throttleMode,
		"ThrottleJSON":    throttleJSON,
		"FilterJSON":      filterJSON,
		"TitleTemplate":   titleTemplate,
		"ContentTemplate": contentTemplate,
		"UPDATE_TIME":     customtype.JsonTime(time.Now()),
	}
	return global.GWAF_LOCAL_DB.Model(model.NotifySubscription{}).Where("id = ?", id).Updates(editMap).Error
}

// SaveConfigPartialApi 按需保存部分配置（批量套用时使用）
func (receiver *WafNotifySubscriptionService) SaveConfigPartialApi(id string, editMap map[string]interface{}) error {
	if len(editMap) == 0 {
		return nil
	}
	editMap["UPDATE_TIME"] = customtype.JsonTime(time.Now())
	return global.GWAF_LOCAL_DB.Model(model.NotifySubscription{}).Where("id = ?", id).Updates(editMap).Error
}

// GetSubscriptionsByChannelType 取某类渠道下的全部订阅（批量套用配置用）
func (receiver *WafNotifySubscriptionService) GetSubscriptionsByChannelType(channelType string) []model.NotifySubscription {
	var subs []model.NotifySubscription
	var channels []model.NotifyChannel
	global.GWAF_LOCAL_DB.Where("type = ?", channelType).Find(&channels)
	if len(channels) == 0 {
		return subs
	}
	ids := make([]string, 0, len(channels))
	for _, ch := range channels {
		ids = append(ids, ch.Id)
	}
	global.GWAF_LOCAL_DB.Where("channel_id in ?", ids).Find(&subs)
	return subs
}

// GetSubscriptionsByMessageTypeAll 取某消息类型的全部订阅（含已禁用，批量套用配置用）
func (receiver *WafNotifySubscriptionService) GetSubscriptionsByMessageTypeAll(messageType string) []model.NotifySubscription {
	var subs []model.NotifySubscription
	global.GWAF_LOCAL_DB.Where("message_type = ?", messageType).Find(&subs)
	return subs
}

// GetSubscriptionsByMessageType 根据消息类型获取订阅
func (receiver *WafNotifySubscriptionService) GetSubscriptionsByMessageType(messageType string) []model.NotifySubscription {
	var subscriptions []model.NotifySubscription
	global.GWAF_LOCAL_DB.Where("message_type = ? and "+dialect.Q("status")+" = ?", messageType, 1).Find(&subscriptions)
	return subscriptions
}
