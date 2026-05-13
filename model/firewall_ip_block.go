package model

import (
	"SamWaf/model/baseorm"
)

// FirewallIPBlock 防火墙IP封禁记录表（操作系统级别的防火墙封禁）
type FirewallIPBlock struct {
	baseorm.BaseOrm
	HostCode   string `gorm:"size:64" json:"host_code"`  // 网站唯一码（主要键）
	IP         string `gorm:"size:64" json:"ip"`         // 被封禁的IP地址，支持单个IP或CIDR格式
	Reason     string `gorm:"type:text" json:"reason"`   // 封禁原因
	BlockType  string `gorm:"size:32" json:"block_type"` // 封禁类型：manual-手动封禁, auto-自动封禁, temp-临时封禁
	Status     string `gorm:"size:16" json:"status"`     // 状态：active-已生效, inactive-已失效, pending-待生效
	ExpireTime int64  `json:"expire_time"`               // 过期时间（时间戳，0表示永久）
	Remarks    string `gorm:"size:500" json:"remarks"`   // 备注
}

// TableName 表名
func (FirewallIPBlock) TableName() string {
	return "firewall_ip_block"
}
