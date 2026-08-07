package model

import (
	"SamWaf/model/baseorm"
)

// HostGuardOffender 攻击者档案(累犯记忆)，阶梯递进封禁的依据。
//
// **为什么用表而不是缓存**：缓存默认是进程内内存(GCACHE_TYPE=memory)，重启即丢，
// 累犯次数一归零，阶梯就永远停在第 1 级，"5分→15分→60分→1天→永久"的递进形同虚设。
// 而且用户需要能直接看到"这个 IP 被我封过 7 次"。
type HostGuardOffender struct {
	baseorm.BaseOrm
	IP             string `gorm:"size:64" json:"ip"`            // 攻击者IP
	Source         string `gorm:"size:16" json:"source"`        // 最近一次的来源 ssh / rdp
	BanCount       int64  `json:"ban_count"`                    // 历史累计封禁次数
	CurrentLevel   int    `json:"current_level"`                // 当前所处阶梯级别
	FirstBanTime   int64  `json:"first_ban_time"`               // 首次封禁时间(unix秒)
	LastBanTime    int64  `json:"last_ban_time"`                // 最近一次封禁时间(unix秒)，记忆期从这里算
	TotalFailCount int64  `json:"total_fail_count"`             // 累计登录失败次数
	LastReason     string `gorm:"type:text" json:"last_reason"` // 最近一次封禁原因
	Location       string `gorm:"size:128" json:"location"`     // 归属地
}

// TableName 表名
func (HostGuardOffender) TableName() string {
	return "host_guard_offender"
}
