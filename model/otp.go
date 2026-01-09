package model

import "SamWaf/model/baseorm"

type Otp struct {
	baseorm.BaseOrm
	UserName string `json:"user_name"` //用户名
	Url      string `json:"url"`       //URL
	Secret   string `json:"secret"`    //密钥
	Issuer   string `json:"issuer"`    //发行者标识
	Remarks  string `json:"remarks"`   //备注
}
