package model

import "time"

/*
*
系统配置
*/
type SystemConfig struct {
	Id             string    `gorm:"primary_key" json:"id"`
	UserCode       string    `json:"user_code"` //用户码（主要键）
	TenantId       string    `json:"tenant_id"` //租户ID（主要键）
	IsSystem       string    `json:"is_system"` //是否是系统值
	Item           string    `json:"item"`
	Value          string    `json:"value"`
	HashInfo       string    `json:"hash_info"`
	Remarks        string    `json:"remarks"`          //备注
	CreateTime     time.Time `json:"create_time"`      //创建时间
	LastUpdateTime time.Time `json:"last_update_time"` //上次更新时间
}
