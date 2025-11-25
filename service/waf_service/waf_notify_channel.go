package waf_service

import (
	"SamWaf/common/uuid"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/request"
	"SamWaf/wafnotify/dingtalk"
	"SamWaf/wafnotify/feishu"
	"errors"
	"time"
)

type WafNotifyChannelService struct{}

var WafNotifyChannelServiceApp = new(WafNotifyChannelService)

// AddApi 添加通知渠道
func (receiver *WafNotifyChannelService) AddApi(req request.WafNotifyChannelAddReq) error {
	var bean = &model.NotifyChannel{
		BaseOrm: baseorm.BaseOrm{
			Id:          uuid.GenUUID(),
			USER_CODE:   global.GWAF_USER_CODE,
			Tenant_ID:   global.GWAF_TENANT_ID,
			CREATE_TIME: customtype.JsonTime(time.Now()),
			UPDATE_TIME: customtype.JsonTime(time.Now()),
		},
		Name:        req.Name,
		Type:        req.Type,
		WebhookURL:  req.WebhookURL,
		Secret:      req.Secret,
		AccessToken: req.AccessToken,
		ConfigJSON:  req.ConfigJSON,
		Status:      req.Status,
		Remarks:     req.Remarks,
	}
	return global.GWAF_LOCAL_DB.Create(bean).Error
}

// CheckIsExistApi 检查是否存在
func (receiver *WafNotifyChannelService) CheckIsExistApi(req request.WafNotifyChannelAddReq) error {
	return global.GWAF_LOCAL_DB.First(&model.NotifyChannel{}, "name = ? ", req.Name).Error
}

// ModifyApi 修改通知渠道
func (receiver *WafNotifyChannelService) ModifyApi(req request.WafNotifyChannelEditReq) error {
	editMap := map[string]interface{}{
		"Name":        req.Name,
		"Type":        req.Type,
		"WebhookURL":  req.WebhookURL,
		"Secret":      req.Secret,
		"AccessToken": req.AccessToken,
		"ConfigJSON":  req.ConfigJSON,
		"Status":      req.Status,
		"Remarks":     req.Remarks,
		"UPDATE_TIME": customtype.JsonTime(time.Now()),
	}
	return global.GWAF_LOCAL_DB.Model(model.NotifyChannel{}).Where("id = ?", req.Id).Updates(editMap).Error
}

// GetDetailApi 获取详情
func (receiver *WafNotifyChannelService) GetDetailApi(req request.WafNotifyChannelDetailReq) model.NotifyChannel {
	var bean model.NotifyChannel
	global.GWAF_LOCAL_DB.Where("id=?", req.Id).Find(&bean)
	return bean
}

// GetListApi 获取列表
func (receiver *WafNotifyChannelService) GetListApi(req request.WafNotifyChannelSearchReq) ([]model.NotifyChannel, int64, error) {
	var list []model.NotifyChannel
	var total int64 = 0

	var whereField = ""
	var whereValues []interface{}

	if len(req.Name) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " name like ? "
		whereValues = append(whereValues, "%"+req.Name+"%")
	}

	if len(req.Type) > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " type = ? "
		whereValues = append(whereValues, req.Type)
	}

	if req.Status > 0 {
		if len(whereField) > 0 {
			whereField = whereField + " and "
		}
		whereField = whereField + " status = ? "
		whereValues = append(whereValues, req.Status)
	}

	global.GWAF_LOCAL_DB.Model(&model.NotifyChannel{}).Where(whereField, whereValues...).Limit(req.PageSize).Offset(req.PageSize * (req.PageIndex - 1)).Find(&list)
	global.GWAF_LOCAL_DB.Model(&model.NotifyChannel{}).Where(whereField, whereValues...).Count(&total)

	return list, total, nil
}

// DelApi 删除
func (receiver *WafNotifyChannelService) DelApi(req request.WafNotifyChannelDelReq) error {
	var bean model.NotifyChannel
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&bean).Error
	if err != nil {
		return err
	}

	// 删除关联的订阅
	global.GWAF_LOCAL_DB.Where("channel_id = ?", req.Id).Delete(&model.NotifySubscription{})

	// 删除渠道
	return global.GWAF_LOCAL_DB.Where("id = ?", req.Id).Delete(&model.NotifyChannel{}).Error
}

// TestChannelApi 测试通知渠道
func (receiver *WafNotifyChannelService) TestChannelApi(req request.WafNotifyChannelTestReq) error {
	var channel model.NotifyChannel
	err := global.GWAF_LOCAL_DB.Where("id = ?", req.Id).First(&channel).Error
	if err != nil {
		return errors.New("通知渠道不存在")
	}

	title := "SamWAF 测试通知"
	content := "这是一条测试消息，发送时间：" + time.Now().Format("2006-01-02 15:04:05")

	switch channel.Type {
	case "dingtalk":
		notifier := dingtalk.NewDingTalkNotifier(channel.WebhookURL, channel.Secret)
		return notifier.SendMarkdown(title, content)
	case "feishu":
		notifier := feishu.NewFeishuNotifier(channel.WebhookURL, channel.Secret)
		return notifier.SendMarkdown(title, content)
	default:
		return errors.New("不支持的通知类型")
	}
}

// GetAllChannels 获取所有启用的通知渠道
func (receiver *WafNotifyChannelService) GetAllChannels() []model.NotifyChannel {
	var channels []model.NotifyChannel
	global.GWAF_LOCAL_DB.Where("status = ?", 1).Find(&channels)
	return channels
}
