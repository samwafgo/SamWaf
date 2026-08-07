package model

import (
	"SamWaf/model/baseorm"
)

// 主机登录失败事件的处置结果
const (
	HostEventActionObserve = "observe" // 观察模式：本应处置但只记录
	HostEventActionCounted = "counted" // 已计入阈值，尚未触发封禁
	HostEventActionSkipped = "skipped" // 白名单豁免或软失败不计数
	HostEventActionBanned  = "banned"  // 本条触发了封禁
)

// HostLoginEvent 主机远程登录(SSH/RDP)失败事件。
//
// 放 log 库：这张表随攻击量线性增长，与 web_logs 同属"可按保留策略清理的观测数据"，
// 不该和核心配置挤在一个库里。
type HostLoginEvent struct {
	baseorm.BaseOrm
	Source    string `gorm:"size:16" json:"source"`     // ssh / rdp
	IP        string `gorm:"size:64" json:"ip"`         // 来源IP
	Port      int    `json:"port"`                      // 源端口，0=未知
	UserName  string `gorm:"size:128" json:"user_name"` // 尝试的用户名
	FailKind  string `gorm:"size:32" json:"fail_kind"`  // 失败类型，见 wafhostguard.FailKind
	LogonType string `gorm:"size:8" json:"logon_type"`  // 仅 Windows：3=Network 10=RemoteInteractive
	Location  string `gorm:"size:128" json:"location"`  // IP归属地
	Action    string `gorm:"size:16" json:"action"`     // observe / counted / skipped / banned
	HitCount  int64  `json:"hit_count"`                 // 触发时窗口内累计次数(仅 banned 行有意义)
	RawLine   string `gorm:"size:500" json:"raw_line"`  // 原始日志行，已截断
	EventTime int64  `json:"event_time"`                // 事件时间(unix秒)
}

// TableName 表名
func (HostLoginEvent) TableName() string {
	return "host_login_event"
}
