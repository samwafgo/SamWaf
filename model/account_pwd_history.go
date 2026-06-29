package model

import (
	"SamWaf/model/baseorm"
)

// AccountPwdHistory 账号历史口令指纹，用于「历史密码防重用」。
// 仅保存口令的 MD5+盐 指纹，不保存明文；按账号保留最近 N 条。
type AccountPwdHistory struct {
	baseorm.BaseOrm
	LoginAccount string `gorm:"size:100;index" json:"login_account"` //登录账号
	PasswordHash string `gorm:"size:255" json:"password_hash"`       //口令指纹(md5+盐)
}
