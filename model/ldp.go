package model

import "time"

/*
*

	隐私处理
*/
type LDPUrl struct {
	Id             int       `gorm:"primary_key" json:" - "`
	UserCode       string    `json:"user_code"`        //用户码（主要键）
	TenantId       string    `json:"tenant_id"`        //租户ID（主要键）
	HostCode       string    `json:"host_code"`        //网站唯一码（主要键）
	Url            string    `json:"url"`              //请求地址
	CreateTime     time.Time `json:"create_time"`      //创建时间
	LastUpdateTime time.Time `json:"last_update_time"` //上次更新时间
}
