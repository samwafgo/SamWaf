package model

import (
	"SamWaf/model/baseorm"
)

// FirewallIPBlock 防火墙IP封禁记录表（操作系统级别的防火墙封禁）
type FirewallIPBlock struct {
	baseorm.BaseOrm
	HostCode   string `json:"host_code"`   // 网站唯一码（主要键）
	IP         string `json:"ip"`          // 被封禁的IP地址，支持单个IP或CIDR格式
	Reason     string `json:"reason"`      // 封禁原因
	BlockType  string `json:"block_type"`  // 封禁类型：manual-手动封禁, auto-自动封禁, temp-临时封禁
	Status     string `json:"status"`      // 状态：active-已生效, inactive-已失效, pending-待生效
	ExpireTime int64  `json:"expire_time"` // 过期时间（时间戳，0表示永久）
	Remarks    string `json:"remarks"`     // 备注
}

// TableName 表名
func (FirewallIPBlock) TableName() string {
	return "firewall_ip_block"
}
