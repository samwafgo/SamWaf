package model

import (
	"SamWaf/model/baseorm"
)

// 封禁状态
const (
	HostBanStatusActive   = "active"   // 生效中
	HostBanStatusExpired  = "expired"  // 到期自动解封
	HostBanStatusReleased = "released" // 被手工提前解封
)

// 封禁执行方式
const (
	HostBanExecIPSet = "ipset" // 走专用集合(Linux ipset / Windows 分片规则 / macOS pf table)
	HostBanExecRule  = "rule"  // 走逐条防火墙规则
)

// HostGuardBan 主机防爆破的封禁账本。
//
// 刻意不复用 firewall_ip_block：那张表服务的是"手工/站点级逐条封禁"，解封走
// UnblockIP 逐条删规则；而防爆破是高频、大批量、集合式封禁，解封只是从集合里删元素。
// 混在一张表里就得改已经稳定的 ClearExpiredRules 分支逻辑，风险不值当。
//
// 记录只置状态不删行：攻击历史要留作取证，也是攻击者档案的佐证。
type HostGuardBan struct {
	baseorm.BaseOrm
	IP         string `gorm:"size:64" json:"ip"`        // 被封禁的IP或网段(网段聚合时是 CIDR)
	Source     string `gorm:"size:16" json:"source"`    // ssh / rdp
	Level      int    `json:"level"`                    // 命中的阶梯级别
	BanMinutes int64  `json:"ban_minutes"`              // 本次封禁时长(分钟)，0=永久
	StartTime  int64  `json:"start_time"`               // 封禁开始(unix秒)
	ExpireTime int64  `json:"expire_time"`              // 到期时间(unix秒)，0=永久
	Reason     string `gorm:"type:text" json:"reason"`  // 封禁原因(中文，直接展示给用户)
	Status     string `gorm:"size:16" json:"status"`    // active / expired / released
	ExecMode   string `gorm:"size:16" json:"exec_mode"` // ipset / rule
	IsSubnet   int    `json:"is_subnet"`                // 1=网段聚合封禁
	HitCount   int64  `json:"hit_count"`                // 触发时窗口内失败次数
	Location   string `gorm:"size:128" json:"location"` // 归属地
	Remarks    string `gorm:"size:500" json:"remarks"`  // 备注
}

// TableName 表名
func (HostGuardBan) TableName() string {
	return "host_guard_ban"
}
