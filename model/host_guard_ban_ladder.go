package model

import (
	"SamWaf/model/baseorm"
)

// HostGuardBanLadder 阶梯封禁配置。第 N 次被封就用第 N 级的时长，
// 超出最高级则一直用最高级。默认播种 5 级：5分 / 15分 / 60分 / 1天 / 永久。
//
// 做成表而不是配置项，是因为级数本身要能增删——有人只想要两级，
// 有人想要更细的爬坡，写死成几个配置项反而束手束脚。
type HostGuardBanLadder struct {
	baseorm.BaseOrm
	Level      int    `json:"level"`                   // 级别，从 1 开始递增
	BanMinutes int64  `json:"ban_minutes"`             // 该级封禁时长(分钟)，0=永久
	Enable     int    `json:"enable"`                  // 1=启用 0=禁用(禁用后跳过该级)
	Remarks    string `gorm:"size:500" json:"remarks"` // 说明
}

// TableName 表名
func (HostGuardBanLadder) TableName() string {
	return "host_guard_ban_ladder"
}

// DefaultBanLadders 默认阶梯。迁移时播种，用户可在页面上改。
func DefaultBanLadders() []HostGuardBanLadder {
	return []HostGuardBanLadder{
		{Level: 1, BanMinutes: 5, Enable: 1, Remarks: "首次触发，多半是自己敲错密码或扫描器路过，短封即可"},
		{Level: 2, BanMinutes: 15, Enable: 1, Remarks: "第二次"},
		{Level: 3, BanMinutes: 60, Enable: 1, Remarks: "第三次"},
		{Level: 4, BanMinutes: 1440, Enable: 1, Remarks: "第四次，封一天"},
		{Level: 5, BanMinutes: 0, Enable: 1, Remarks: "惯犯母机，永久封禁(0表示永久)"},
	}
}
