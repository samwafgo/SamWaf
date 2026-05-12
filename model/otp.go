package model

import "SamWaf/model/baseorm"

type Otp struct {
	baseorm.BaseOrm
	UserName string `gorm:"size:255" json:"user_name"` //用户名
	Url      string `gorm:"size:500" json:"url"`       //URL
	Secret   string `gorm:"size:255" json:"secret"`    //密钥
	Issuer   string `gorm:"size:255" json:"issuer"`    //发行者标识
	Remarks  string `gorm:"size:500" json:"remarks"`   //备注
}
