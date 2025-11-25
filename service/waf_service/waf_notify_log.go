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

type WafNotifyLogService struct{}

var WafNotifyLogServiceApp = new(WafNotifyLogService)

// AddLog 添加通知日志
func (receiver *WafNotifyLogService) AddLog(channelId, channelName, channelType, messageType, messageTitle, messageContent string, status int, errorMsg string) error {
	var bean = &model.NotifyLog{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		ChannelId:      channelId,
		ChannelName:    channelName,
		ChannelType:    channelType,
		MessageType:    messageType,
		MessageTitle:   messageTitle,
		MessageContent: messageContent,
		Status:         status,
		ErrorMsg:       errorMsg,
		SendTime:       time.Now().Format("2006-01-02 15:04:05"),
	}
	return global.GWAF_LOCAL_LOG_DB.Create(bean).Error
}

// GetListApi 获取列表
func (receiver *WafNotifyLogService) GetListApi(req request.WafNotifyLogSearchReq) ([]model.NotifyLog, int64, error) {
	var list []model.NotifyLog
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

	if len(req.StartTime) > 0 && len(req.EndTime) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " send_time >= ? and send_time <= ? "
		whereValues = append(whereValues, req.StartTime, req.EndTime)
	}

	global.GWAF_LOCAL_LOG_DB.Model(&model.NotifyLog{}).Where(whereField, whereValues...).Order("create_time desc").Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_LOG_DB.Model(&model.NotifyLog{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}

// GetDetailApi 获取详情
func (receiver *WafNotifyLogService) GetDetailApi(req request.WafNotifyLogDetailReq) model.NotifyLog {
	var bean model.NotifyLog
	global.GWAF_LOCAL_LOG_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}

// DelApi 删除
func (receiver *WafNotifyLogService) DelApi(req request.WafNotifyLogDelReq) error {
	return global.GWAF_LOCAL_LOG_DB.Where("id = ?", req.Id).Delete(&model.NotifyLog{}).Error
}
