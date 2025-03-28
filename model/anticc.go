package model

import "SamWaf/model/baseorm"

/**

- 平均速率模式 ：将请求平均分配到每一秒，适合防止突发攻击
- 滑动窗口模式 ：严格按照"N秒内最多M次"的规则限流，更符合直观理解
**/

type AntiCC struct {
	baseorm.BaseOrm
	Id            string `json:"id" gorm:"column:id;primary_key"`
	HostCode      string `json:"host_code" gorm:"column:host_code"`
	Rate          int    `json:"rate" gorm:"column:rate"`
	Limit         int    `json:"limit" gorm:"column:limit"`
	LockIPMinutes int    `json:"lock_ip_minutes" gorm:"column:lock_ip_minutes"`
	LimitMode     string `json:"limit_mode" gorm:"column:limit_mode"` // "rate" 或 "window"
	Url           string `json:"url"`                                 //保护的url
	Remarks       string `json:"remarks"`                             //备注
}
