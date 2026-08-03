package model

import (
	"SamWaf/model/baseorm"
)

// ThreatIPChannel 威胁情报 IP 订阅渠道配置表。
// 每个渠道每天提供一份全量 IP/CIDR 快照(如 USTC blackip、stamparm/ipsum)，
// 系统按周期拉取、计算差异后落地到 WAF 应用层大集合或系统防火墙(ipset)。
type ThreatIPChannel struct {
	baseorm.BaseOrm
	Code         string `gorm:"size:32;index" json:"code"`   // 渠道短码(小写字母/数字/下划线，≤24)，用作 ipset 名 samwaf_sub_<code>
	Name         string `gorm:"size:128" json:"name"`        // 显示名，如 "USTC blackip"
	URL          string `gorm:"type:text" json:"url"`        // 拉取地址
	ParserType   string `gorm:"size:32" json:"parser_type"`  // 解析器：plain_mixed | ipsum | cidr_only
	Threshold    int    `json:"threshold"`                   // ipsum 命中黑名单数阈值(≥该值才收)，其它解析器忽略
	LandTarget   string `gorm:"size:16" json:"land_target"`  // 落地层：waf | system | both
	Enable       int    `json:"enable"`                      // 是否启用：0 停用，1 启用
	IntervalHour int    `json:"interval_hour"`               // 拉取周期(小时)，默认 24
	LastSyncAt   int64  `json:"last_sync_at"`                // 上次成功同步时间戳(秒)
	LastCount    int    `json:"last_count"`                  // 上次快照收录条数
	LastStatus   string `gorm:"size:255" json:"last_status"` // 上次同步结果：ok 或错误摘要
	Remarks      string `gorm:"size:500" json:"remarks"`     // 备注
}

// TableName 表名
func (ThreatIPChannel) TableName() string {
	return "threat_ip_channel"
}

// 落地层枚举
const (
	ThreatLandWAF    = "waf"
	ThreatLandSystem = "system"
	ThreatLandBoth   = "both"
)

// 解析器类型枚举
const (
	ThreatParserPlainMixed = "plain_mixed"
	ThreatParserIpsum      = "ipsum"
	ThreatParserCIDROnly   = "cidr_only"
)
