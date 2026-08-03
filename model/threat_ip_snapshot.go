package model

import (
	"SamWaf/model/baseorm"
)

// ThreatIPSnapshot 威胁情报渠道的紧凑快照表。
// 关键设计：每个渠道每个 IP 版本只存 1 行(而非每 IP 一行)，Payload 为 gzip 压缩后的
// \n 分隔 IP/CIDR 文本。十万条压缩后约 300KB~1MB，避免了逐行入库导致的爆表与 O(n) 写放大；
// 内存态才展开为集合用于 diff 与落地。
type ThreatIPSnapshot struct {
	baseorm.BaseOrm
	ChannelCode string `gorm:"size:32;index" json:"channel_code"` // 渠道短码；CDN 预设段用 __cdn_<provider>__
	IPVersion   int    `json:"ip_version"`                        // 4 或 6，分开存便于分别灌入 v4/v6 集合
	Count       int    `json:"count"`                             // 本快照条数
	Payload     []byte `gorm:"column:payload" json:"-"`           // gzip 压缩的 \n 分隔 IP/CIDR 文本(跨库: sqlite BLOB / mysql blob / pg bytea，勿写死 type)
	Sha256      string `gorm:"size:64" json:"sha256"`             // 原始文本 sha256，用于判定是否变化
}

// TableName 表名
func (ThreatIPSnapshot) TableName() string {
	return "threat_ip_snapshot"
}
