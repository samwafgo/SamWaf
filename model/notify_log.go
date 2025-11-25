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
	ChannelId      string `json:"channel_id"`      // 渠道ID
	ChannelName    string `json:"channel_name"`    // 渠道名称
	ChannelType    string `json:"channel_type"`    // 渠道类型
	MessageType    string `json:"message_type"`    // 消息类型
	MessageTitle   string `json:"message_title"`   // 消息标题
	MessageContent string `json:"message_content"` // 消息内容
	Status         int    `json:"status"`          // 发送状态：1成功，0失败
	ErrorMsg       string `json:"error_msg"`       // 错误信息
	SendTime       string `json:"send_time"`       // 发送时间
}
