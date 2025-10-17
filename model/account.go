package model

import (
	"SamWaf/model/baseorm"
)

type Account struct {
	baseorm.BaseOrm
	LoginAccount  string `json:"login_account"`  //登录账号
	LoginPassword string `json:"login_password"` //密码md5加密
	Role          string `json:"role"`           //登录角色
	Status        int    `json:"status"`         //状态
	Remarks       string `json:"remarks"`        //备注
}

type AccountLog struct {
	baseorm.BaseOrm
	LoginAccount string `json:"login_account"` //登录账号
	OpType       string `json:"op_type"`       //操作类型
	OpContent    string `json:"op_content"`    //操作内容
}
type TokenInfo struct {
	baseorm.BaseOrm
	LoginAccount      string `json:"login_account"`             //登录账号
	LoginIp           string `json:"login_ip"`                  //登录IP
	AccessToken       string `json:"access_token" crypto:"aes"` //访问码
	DeviceFingerprint string `json:"device_fingerprint"`        //设备指纹
	LoginType         string `json:"login_type"`                //登录类型 web/mobile
}
