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

	// LandedSha/LandedCount 记录"**已确认落地到系统防火墙**的那份快照"。
	//
	// 必须与 threat_ip_snapshot.Sha256(内容态)分开：一个字段没法同时表达
	// "内容变没变"和"落地成功没有"。Windows 上一次全量重建是几十次独立 netsh 调用，
	// 中途失败会留下半截规则；若此时仍按内容 sha 判定"无变化"，就会永远跳过落地，
	// 页面显示 ok、实际只封了一半，且再也不会自愈。
	// 有了这两个字段，判据变成"内容没变 **且** 落地态等于内容态"才能跳过。
	LandedSha   string `gorm:"size:64" json:"landed_sha"` // 已落地快照的 sha256，空=从未确认落地
	LandedCount int    `json:"landed_count"`              // 已落地的条数

	// 以下为运行时内存态字段(gorm:"-" 不落库，无需迁移)，仅供列表接口回显"同步中"，
	// 让前端能在后台拉取期间给出反馈并自动轮询，而不是点完什么都看不到。
	Syncing       bool  `gorm:"-" json:"syncing"`         // 该渠道当前是否有同步在进行
	SyncStartedAt int64 `gorm:"-" json:"sync_started_at"` // 本次同步开始时间戳(秒)，Syncing 为 false 时无意义
	// LandedOK 系统防火墙是否已确认落地到当前应有的内容(有效集)。由服务端比对 LandedSha 与有效集 sha 得出，
	// 不让前端拿条数去猜(落地层不含系统层、环境不支持 ipset 等情况都不该报警)。
	LandedOK bool `gorm:"-" json:"landed_ok"`
	// ExcludedCount 本渠道被误报排除名单剔掉的条数(内容集 - 有效集)。
	// 页面据此显示"已排除 N 条"，让用户知道防火墙里的数字为什么比收录条数少。
	ExcludedCount int `gorm:"-" json:"excluded_count"`
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
