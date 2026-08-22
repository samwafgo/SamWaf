package model

import (
	"SamWaf/customtype"
	"SamWaf/model/baseorm"
)

// 升级须知的处理状态
const (
	UpgradeNoticeStatusPending = "pending" // 待处理
	UpgradeNoticeStatusDone    = "done"    // 已处理
	UpgradeNoticeStatusIgnored = "ignored" // 已忽略
)

// UpgradeNoticeRecord 升级须知的处理状态。
//
// 只落 notice_id 与状态，**文案不落库** —— 渲染时用当前二进制内置清单里的文案。
// 这样文案修订随版本走，库里也不会堆冗余文本；代价是清单里被删掉的条目会在库里
// 留下孤儿记录，列表侧按 notice_id 过滤掉即可。
type UpgradeNoticeRecord struct {
	baseorm.BaseOrm
	NoticeId    string              `gorm:"size:100;index" json:"notice_id"` // 对应内置清单的 id
	Version     string              `gorm:"size:32" json:"version"`          // 条目所属版本
	FromVersion string              `gorm:"size:32" json:"from_version"`     // 本次升级的起点
	ToVersion   string              `gorm:"size:32" json:"to_version"`       // 本次升级的终点
	Kind        string              `gorm:"size:20" json:"kind"`             // notice / action / check
	Level       string              `gorm:"size:20" json:"level"`            // high / normal / low
	Status      string              `gorm:"size:20;index" json:"status"`     // pending / done / ignored
	OldValue    string              `gorm:"type:text" json:"old_value"`      // v2 一键应用前的原值，供撤销
	AppliedTime customtype.JsonTime `json:"applied_time"`                    // 处理时间
	AppliedUser string              `gorm:"size:64" json:"applied_user"`     // 处理人
	PopupShown  int                 `json:"popup_shown"`                     // 1=已弹过窗，此后不再弹
}

// TableName 表名
func (UpgradeNoticeRecord) TableName() string {
	return "upgrade_notice_record"
}
