package model

import (
	"SamWaf/model/baseorm"
)

/*
*
通知发送日志
*/
type NotifyLog struct {
	baseorm.BaseOrm
	ChannelId      string `gorm:"size:64" json:"channel_id"`        // 渠道ID
	ChannelName    string `gorm:"size:255" json:"channel_name"`     // 渠道名称
	ChannelType    string `gorm:"size:50" json:"channel_type"`      // 渠道类型
	MessageType    string `gorm:"size:100" json:"message_type"`     // 消息类型
	MessageTitle   string `gorm:"size:500" json:"message_title"`    // 消息标题
	MessageContent string `gorm:"type:text" json:"message_content"` // 消息内容
	Recipients     string `gorm:"type:text" json:"recipients"`      // 收件人（仅邮件类型）
	Status         int    `json:"status"`                           // 发送状态：1成功，0失败
	ErrorMsg       string `gorm:"type:text" json:"error_msg"`       // 错误信息
	SendTime       string `gorm:"size:100" json:"send_time"`        // 发送时间
}
