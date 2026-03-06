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
	KeyName     string `json:"key_name"`      //Key 名称
	ApiKey      string `json:"api_key"`       //API Key（自动生成，用于 X-API-Key 请求头鉴权）
	Status      int    `json:"status"`        //状态 1启用 0禁用
	Remark      string `json:"remark"`        //备注
	RateLimit   int64  `json:"rate_limit"`    //每分钟限流次数，0不限
	IPWhitelist string `json:"ip_whitelist"`  //IP白名单，逗号分隔，空不限
	ExpireTime  string `json:"expire_time"`   //过期时间，空不过期
	LastUseTime string `json:"last_use_time"` //最后使用时间
	CallCount   int64  `json:"call_count"`    //累计调用次数
}
