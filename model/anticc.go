package model

import "time"

type AntiCC struct {
	Id             string    `gorm:"primary_key" json:"id"`
	UserCode       string    `json:"user_code"`        //用户码（主要键）
	TenantId       string    `json:"tenant_id"`        //租户ID（主要键）
	HostCode       string    `json:"host_code"`        //网站唯一码（主要键）
	Rate           int       `json:"rate"`             //速率
	Limit          int       `json:"limit"`            //限制
	Url            string    `json:"url"`              //保护的url
	Remarks        string    `json:"remarks"`          //备注
	CreateTime     time.Time `json:"create_time"`      //创建时间
	LastUpdateTime time.Time `json:"last_update_time"` //上次更新时间
}
