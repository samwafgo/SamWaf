package model

import (
	"SamWaf/model/baseorm"
)

// IP 黑/白名单的条目类型
//
// 存量数据的 ip_type 是 NULL/""，含义与 IPEntryTypeIP 相同。
// ⚠️ 因此所有判定必须写 `== IPEntryTypeGroup`，绝不能写 `!= IPEntryTypeIP`——
// 后者会把全部存量行判成组引用，导致升级瞬间所有黑/白名单失效。
const (
	IPEntryTypeIP    = "ip"    // 单条：单IP / CIDR / 通配符 / 区间
	IPEntryTypeGroup = "group" // 引用一个 IP 组
)

// IPGroup 是可跨站点复用的 IP 集合。
//
// 与黑/白名单不同，IP 组不带 host_code：它是租户级资源，由多个站点的黑/白名单条目
// 以及自定义规则(RF.IPInGroup)共同引用。组内容变更后，所有引用方(含全局网站)立即生效，
// 靠的是 wafenginecore/ipset 里的全局原子快照，而不是逐站点下发消息。
type IPGroup struct {
	baseorm.BaseOrm
	GroupName string `gorm:"size:255" json:"group_name"` //组名称（展示用，规则里 RF.IPInGroup 也可直接写它）
	GroupCode string `gorm:"size:64"  json:"group_code"` //组短码，创建后不可修改（黑/白名单与规则引用它）
	Remarks   string `gorm:"size:500" json:"remarks"`    //备注
	ItemCount int    `gorm:"-"        json:"item_count"` //组内条目数，列表接口聚合填充，不落库
}

func (IPGroup) TableName() string {
	return "ip_group"
}

// IPGroupItem 是 IP 组内的一条 IP 模式。
//
// Ip 列长度用 128 而非黑/白名单历史沿用的 64：IPv6 闭区间最长可达 79 字符
// (39 + '-' + 39)，64 位会被截断（SQLite 静默截断、MySQL 严格模式直接报错）。
type IPGroupItem struct {
	baseorm.BaseOrm
	GroupCode string `gorm:"size:64"  json:"group_code"` //所属组短码
	Ip        string `gorm:"size:128" json:"ip"`         //单IP / CIDR / 通配符 / 区间，语法见 wafenginecore/ipset/pattern.go
	Remarks   string `gorm:"size:500" json:"remarks"`    //备注
}

func (IPGroupItem) TableName() string {
	return "ip_group_item"
}
