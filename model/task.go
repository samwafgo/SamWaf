package model

import "SamWaf/model/baseorm"

type Task struct {
	baseorm.BaseOrm
	TaskName          string `json:"task_name"`             // 任务名称
	TaskUnit          string `json:"task_unit"`             // 单位
	TaskValue         int    `json:"task_value"`            // 值
	TaskAt            string `json:"task_at"`               // 特定时间
	TaskMethod        string `json:"task_method"`           //关联方法
	TaskDaysOfTheWeek string `json:"task_days_of_the_week"` // 周几 在周级别的情况下才起作用
}
