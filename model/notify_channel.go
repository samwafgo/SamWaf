package model

import (
	"SamWaf/model/baseorm"
)

/*
*
通知渠道配置
*/
type NotifyChannel struct {
	baseorm.BaseOrm
	Name        string `gorm:"size:255" json:"name"`         // 渠道名称
	Type        string `gorm:"size:50" json:"type"`          // 渠道类型：dingtalk, feishu, wechat, email等
	WebhookURL  string `gorm:"size:500" json:"webhook_url"`  // Webhook地址
	Secret      string `gorm:"size:255" json:"secret"`       // 密钥（用于签名验证）
	AccessToken string `gorm:"size:500" json:"access_token"` // 访问令牌
	ConfigJSON  string `gorm:"type:text" json:"config_json"` // 额外配置（JSON格式）
	Status      int    `json:"status"`                       // 状态：1启用，0禁用
	Remarks     string `gorm:"size:500" json:"remarks"`      // 备注
}
