package model

import (
	"SamWaf/model/baseorm"
)

/*
*
开放平台 API Key
*/
type OPlatformKey struct {
	baseorm.BaseOrm
	KeyName     string `gorm:"size:255" json:"key_name"`      //Key 名称
	ApiKey      string `gorm:"size:255" json:"api_key"`       //API Key（自动生成，用于 X-API-Key 请求头鉴权）
	Status      int    `json:"status"`                        //状态 1启用 0禁用
	Remark      string `gorm:"size:500" json:"remark"`        //备注
	RateLimit   int64  `json:"rate_limit"`                    //每分钟限流次数，0不限
	IPWhitelist string `gorm:"type:text" json:"ip_whitelist"` //IP白名单，逗号分隔，空不限
	ExpireTime  string `gorm:"size:50" json:"expire_time"`    //过期时间，空不过期
	LastUseTime string `gorm:"size:50" json:"last_use_time"`  //最后使用时间
	CallCount   int64  `json:"call_count"`                    //累计调用次数
}
