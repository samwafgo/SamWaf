package model

import (
	"SamWaf/model/baseorm"
)

// ThreatIPExcludeAudit 威胁情报排除名单操作审计。
//
// 放日志库(GWAF_LOCAL_LOG_DB)而不是核心库：这是只增不改的审计流水，
// 与 LoginHistory / AccessAuditLog 同性质。
//
// 排除名单是**主动降低防护**的操作，删除排除条目后原记录就没了，
// 所以"曾经排除过什么、谁排的、什么时候"必须单独留一份流水，删除动作本身也要记。
type ThreatIPExcludeAudit struct {
	baseorm.BaseOrm
	Action string `gorm:"size:16;index" json:"action"` // add | del | enable | disable
	Entry  string `gorm:"size:64;index" json:"entry"`  // 排除条目(单 IP 或 CIDR)
	Source string `gorm:"size:16" json:"source"`       // manual | auto
	Reason string `gorm:"size:64" json:"reason"`       // Source=auto 时的自动排除原因

	Operator   string `gorm:"size:64" json:"operator"`    // 操作账号；系统自动固化时为 system
	OperatorIP string `gorm:"size:64" json:"operator_ip"` // 操作来源IP，走 GetManageClientIP(可信代理校验)，不用 c.ClientIP()

	AffectedChans int `json:"affected_chans"` // 本次影响的渠道数
	AffectedItems int `json:"affected_items"` // 本次剔除(或恢复)的威胁情报条数

	Remarks string `gorm:"size:500" json:"remarks"` // 操作备注
}

// TableName 表名
func (ThreatIPExcludeAudit) TableName() string {
	return "threat_ip_exclude_audit"
}

// 审计动作
const (
	ThreatExcludeActionAdd     = "add"
	ThreatExcludeActionDel     = "del"
	ThreatExcludeActionEnable  = "enable"
	ThreatExcludeActionDisable = "disable"
)
