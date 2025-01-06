package model

import "SamWaf/model/baseorm"

type HttpAuthBase struct {
	baseorm.BaseOrm
	HostCode string `json:"host_code"` //网站唯一码（主要键）
	UserName string `json:"user_name"` // 用户名
	Password string `json:"password"`  // 访问密码
}
