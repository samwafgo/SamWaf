package model

import (
	"SamWaf/model/baseorm"
)

/*
*
通知订阅配置
*/
type NotifySubscription struct {
	baseorm.BaseOrm
	ChannelId   string `json:"channel_id"`   // 关联的渠道ID
	MessageType string `json:"message_type"` // 消息类型：user_login, attack_info, weekly_report等
	Status      int    `json:"status"`       // 状态：1启用，0禁用
	FilterJSON  string `json:"filter_json"`  // 过滤条件（JSON格式）
	Remarks     string `json:"remarks"`      // 备注
}

// 消息类型常量
const (
	MSG_TYPE_RULE_TRIGGER     = "rule_trigger"     // 规则触发
	MSG_TYPE_OPERATION_NOTICE = "operation_notice" // 操作通知
	MSG_TYPE_USER_LOGIN       = "user_login"       // 用户登录
	MSG_TYPE_ATTACK_INFO      = "attack_info"      // 攻击信息
	MSG_TYPE_WEEKLY_REPORT    = "weekly_report"    // 周报
	MSG_TYPE_SSL_EXPIRE       = "ssl_expire"       // SSL证书过期
	MSG_TYPE_SYSTEM_ERROR     = "system_error"     // 系统错误
	MSG_TYPE_IP_BAN           = "ip_ban"           // IP封禁
)
