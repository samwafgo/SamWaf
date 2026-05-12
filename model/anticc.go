package model

import "SamWaf/model/baseorm"

/**

- 平均速率模式 ：将请求平均分配到每一秒，适合防止突发攻击
- 滑动窗口模式 ：严格按照"N秒内最多M次"的规则限流，更符合直观理解
**/

type AntiCC struct {
	baseorm.BaseOrm
	HostCode      string `json:"host_code" gorm:"column:host_code;size:64"`
	Rate          int    `json:"rate" gorm:"column:rate"`
	Limit         int    `json:"limit" gorm:"column:limit"`
	LockIPMinutes int    `json:"lock_ip_minutes" gorm:"column:lock_ip_minutes"`
	LimitMode     string `json:"limit_mode" gorm:"column:limit_mode;size:20"` // "rate" 或 "window"
	IPMode        string `json:"ip_mode" gorm:"column:ip_mode;size:20"`       // "nic" 网卡模式 或 "proxy" 代理模式
	Url           string `gorm:"type:text" json:"url"`
	IsEnableRule  bool   `json:"is_enable_rule" gorm:"column:is_enable_rule"`       //是否启动规则
	RuleContent   string `json:"rule_content" gorm:"column:rule_content;type:text"` //规则内容
	SkipGlobalCC  bool   `json:"skip_global_cc" gorm:"column:skip_global_cc"`       //命中局部CC规则后跳过全局CC检测
	Remarks       string `gorm:"size:500" json:"remarks"`                           //备注
}
