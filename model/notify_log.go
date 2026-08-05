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
	Status         int    `json:"status"`                           // 发送状态：1成功，0失败，2被抑制（未发送）
	ErrorMsg       string `gorm:"type:text" json:"error_msg"`       // 错误信息
	SendTime       string `gorm:"size:100" json:"send_time"`        // 发送时间

	// ===== 可调试性（issue #822）=====
	// 老实现只记"发出去的"，用户问"为什么没收到"时无从查起。
	SubscriptionId string `gorm:"size:64" json:"subscription_id"` // 订阅ID，定位到通知订阅页的具体格子
	SuppressReason string `gorm:"size:50" json:"suppress_reason"` // 抑制原因：cooldown/rate_limit/quiet_hours/filter_miss
	SuppressCount  int    `json:"suppress_count"`                 // 本条抑制窗口内累计压掉了多少条
	TemplateUsed   string `gorm:"size:20" json:"template_used"`   // 模板来源：default/custom/custom_fallback
}
