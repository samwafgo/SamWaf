package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
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

	global.GWAF_LOCAL_DB.Model(&model.NotifySubscription{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.NotifySubscription{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}

// DelApi 删除
func (receiver *WafNotifySubscriptionService) DelApi(req request.WafNotifySubscriptionDelReq) error {
	return global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(&model.NotifySubscription{}).Error
}

// GetSubscriptionsByMessageType 根据消息类型获取订阅
func (receiver *WafNotifySubscriptionService) GetSubscriptionsByMessageType(messageType string) []model.NotifySubscription {
	var subscriptions []model.NotifySubscription
	global.GWAF_LOCAL_DB.Where("message_type = ? and status = ?", messageType, 1).Find(&subscriptions)
	return subscriptions
}
