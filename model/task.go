package model

import "SamWaf/model/baseorm"

type Task struct {
	baseorm.BaseOrm
	TaskName          string `gorm:"size:255" json:"task_name"`             // 任务名称
	TaskUnit          string `gorm:"size:50" json:"task_unit"`              // 单位
	TaskValue         int    `json:"task_value"`                            // 值
	TaskAt            string `gorm:"size:100" json:"task_at"`               // 特定时间
	TaskMethod        string `gorm:"size:255" json:"task_method"`           //关联方法
	TaskDaysOfTheWeek string `gorm:"size:100" json:"task_days_of_the_week"` // 周几 在周级别的情况下才起作用
}
