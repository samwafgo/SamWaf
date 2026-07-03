package model

import (
	"SamWaf/model/baseorm"
)

type Account struct {
	baseorm.BaseOrm
	LoginAccount       string `gorm:"size:100" json:"login_account"`  //登录账号
	LoginPassword      string `gorm:"size:255" json:"login_password"` //密码md5加密
	Role               string `gorm:"size:50" json:"role"`            //登录角色 superAdmin/systemAdmin/securityAdmin/auditAdmin
	Status             int    `json:"status"`                         //状态
	NeedChangePassword int    `json:"need_change_password"`           //是否需要强制改密 1需要 0否（首次登录/被重置后置1）
	PwdUpdateTime      string `gorm:"size:32" json:"pwd_update_time"` //上次改密时间(2006-01-02 15:04:05)，用于有效期判断
	Remarks            string `gorm:"size:500" json:"remarks"`        //备注
}

type AccountLog struct {
	baseorm.BaseOrm
	LoginAccount string `gorm:"size:100" json:"login_account"` //登录账号
	OpType       string `gorm:"size:100" json:"op_type"`       //操作类型
	OpContent    string `gorm:"type:text" json:"op_content"`   //操作内容
}
type TokenInfo struct {
	baseorm.BaseOrm
	LoginAccount       string `gorm:"size:100" json:"login_account"`              //登录账号
	LoginIp            string `gorm:"size:64" json:"login_ip"`                    //登录IP
	AccessToken        string `gorm:"type:text" json:"access_token" crypto:"aes"` //访问码
	DeviceFingerprint  string `gorm:"size:255" json:"device_fingerprint"`         //设备指纹
	LoginType          string `gorm:"size:50" json:"login_type"`                  //登录类型 web/mobile
	Role               string `gorm:"size:50" json:"role"`                        //登录角色(冗余自Account，便于鉴权中间件快速判定)
	NeedChangePassword int    `gorm:"-" json:"need_change_password"`              //是否需强制改密：随令牌缓存下发，Auth 中间件据此拦截未改密令牌；不落库(gorm:"-")
}
