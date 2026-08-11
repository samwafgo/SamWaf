package model

import (
	"SamWaf/model/baseorm"
)

// ThreatIPExclude 威胁情报误报排除名单。
//
// 订阅源给的是**全量快照**，每个周期整份覆盖，用户手工从防火墙里删掉的条目下次同步就回来了；
// 落到系统防火墙的部分又是内核丢包，WAF 的 IP 白名单(CheckAllowIP)根本轮不到判定。
// 所以误报必须有一份"跟着每次同步/对账一起重新应用"的本地排除声明。
//
// 本表是**整机级**的(不按站点)：系统防火墙本身就是整机级，用 per-host 白名单驱动整机级排除
// 会出现"A 站点的白名单顺带给 SSH 开门"的语义错配。
type ThreatIPExclude struct {
	baseorm.BaseOrm
	Entry   string `gorm:"size:64;index" json:"entry"` // 单 IP 或 CIDR，如 1.2.3.4 / 1.2.3.0/24
	Source  string `gorm:"size:16" json:"source"`      // 来源：manual 手工添加 | auto 系统自动固化
	Reason  string `gorm:"size:64" json:"reason"`      // Source=auto 时的自动排除原因(loopback/local/lan/config/manage/admin_ip)
	Remarks string `gorm:"size:500" json:"remarks"`    // 备注：为什么认为是误报
	Enable  int    `json:"enable"`                     // 1 生效 0 停用(停用保留记录，便于回溯)

	// HitCount/LastHitAt 记录最近一次计算时这条排除**实际剔除了多少条**威胁情报内容。
	// 用途是让用户一眼看出"写了但没生效"——最典型的是排除了 1.2.3.4，
	// 而快照里其实是 1.2.3.0/24（小的排不掉大的，见设计文档 §5.1）。
	HitCount  int   `json:"hit_count"`
	LastHitAt int64 `json:"last_hit_at"` // 最近一次命中的时间戳(秒)
}

// TableName 表名
func (ThreatIPExclude) TableName() string {
	return "threat_ip_exclude"
}

// 排除条目来源
const (
	ThreatExcludeSourceManual = "manual"
	ThreatExcludeSourceAuto   = "auto"
)
