package model

import "SamWaf/model/baseorm"

type HttpAuthBase struct {
	baseorm.BaseOrm
	HostCode string `gorm:"size:64" json:"host_code"`  //网站唯一码（主要键）
	UserName string `gorm:"size:255" json:"user_name"` // 用户名
	Password string `gorm:"size:255" json:"password"`  // 访问密码
}
