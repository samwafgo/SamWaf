package request

import "SamWaf/model/common/request"

type WafOPlatformKeyAddReq struct {
	KeyName     string `json:"key_name"`     //Key 名称
	Remark      string `json:"remark"`       //备注
	RateLimit   int64  `json:"rate_limit"`   //每分钟限流次数，0不限
	IPWhitelist string `json:"ip_whitelist"` //IP白名单，逗号分隔，空不限
	ExpireTime  string `json:"expire_time"`  //过期时间，空不过期
}

type WafOPlatformKeyDelReq struct {
	Id string `json:"id" form:"id"` //唯一键
}

type WafOPlatformKeyDetailReq struct {
	Id string `json:"id" form:"id"` //唯一键
}

type WafOPlatformKeyEditReq struct {
	Id          string `json:"id"`
	KeyName     string `json:"key_name"`     //Key 名称
	Status      int    `json:"status"`       //状态 1启用 0禁用
	Remark      string `json:"remark"`       //备注
	RateLimit   int64  `json:"rate_limit"`   //每分钟限流次数，0不限
	IPWhitelist string `json:"ip_whitelist"` //IP白名单，逗号分隔，空不限
	ExpireTime  string `json:"expire_time"`  //过期时间，空不过期
}

type WafOPlatformKeySearchReq struct {
	KeyName string `json:"key_name" form:"key_name"` //Key名称
	request.PageInfo
}

type WafOPlatformKeyResetSecretReq struct {
	Id string `json:"id" form:"id"` //唯一键
}
