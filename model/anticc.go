package model

import (
	"SamWaf/model/baseorm"
)

type AntiCC struct {
	baseorm.BaseOrm
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	Rate     int    `json:"rate"`      //速率
	Limit    int    `json:"limit"`     //限制
	Url      string `json:"url"`       //保护的url
	Remarks  string `json:"remarks"`   //备注
}
