package model

import "SamWaf/model/baseorm"

type WafApp struct {
	baseorm.BaseOrm
	Code            string `gorm:"size:64;uniqueIndex" json:"code"`
	Name            string `gorm:"size:128" json:"name"`
	AppDir          string `gorm:"size:512" json:"app_dir"`
	StartCmd        string `gorm:"size:1024" json:"start_cmd"`
	Env             string `gorm:"size:2048" json:"env"`
	AutoStart       int    `json:"auto_start"`
	StartStatus     int    `json:"start_status"`
	StopMode        string `gorm:"size:16" json:"stop_mode"`
	StopCmd         string `gorm:"size:1024" json:"stop_cmd"`
	StopTimeout     int    `json:"stop_timeout"`
	RestartPolicy   string `gorm:"size:16" json:"restart_policy"`
	RestartDelay    int    `json:"restart_delay"`
	MaxRestartCount int    `json:"max_restart_count"`
	LogMaxLines     int    `json:"log_max_lines"`
	Remarks         string `gorm:"size:512" json:"remarks"`
}
