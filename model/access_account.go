package model

import (
	"SamWaf/customtype"
	"SamWaf/model/baseorm"
)

// 访问账号状态
const (
	AccessAccountStatusDisable = 0 // 禁用
	AccessAccountStatusEnable  = 1 // 启用
)

// 账号级 OTP 策略（与全局 require_otp 的关系见 AccessAccount.ForceOtp）
const (
	AccessOtpInherit = 0 // 继承全局
	AccessOtpForce   = 1 // 本账号强制要求
	AccessOtpExempt  = 2 // 本账号豁免
)

// AccessAccount 是「统一访问认证(Access 模式)」的访客账号。
//
// 它与三套已有身份体系都不是一回事，不要混用：
//   - model.Account      —— 管理端 :26666 的管理员，权限极高，绝不能拿来给公网访客登录
//   - model.HttpAuthBase —— 老的「网站密码访问」，账号绑死在单个站点上，明文存密码
//   - AccessAccount      —— 本表，租户级访客账号，一次登录可放行多个站点
//
// 密码用 bcrypt（utils.BcryptHash），OtpSecret 用 wafsec 加密后落库，两者都是 json:"-"，
// 保证任何 API 响应都不会把它们带出去。
type AccessAccount struct {
	baseorm.BaseOrm
	AccountName    string              `gorm:"size:128" json:"account_name"`      //登录名，租户内唯一
	Password       string              `gorm:"size:255" json:"-"`                 //bcrypt 摘要，永不出现在 API 响应里
	NickName       string              `gorm:"size:128" json:"nick_name"`         //显示名
	Status         int                 `json:"status"`                            //1启用 0禁用
	OtpSecret      string              `gorm:"size:512" json:"-"`                 //TOTP 密钥，wafsec 加密后存储
	OtpBound       int                 `json:"otp_bound"`                         //1已绑定 0未绑定
	ForceOtp       int                 `json:"force_otp"`                         //0继承全局 1强制要求 2豁免
	AllowHostCodes string              `gorm:"type:text" json:"allow_host_codes"` //可访问站点的 host_code，换行分隔；空=全部站点
	ExpireTime     customtype.JsonTime `json:"expire_time"`                       //账号有效期，零值=永不过期
	LastLoginTime  customtype.JsonTime `json:"last_login_time"`                   //最后登录时间
	LastLoginIP    string              `gorm:"size:64" json:"last_login_ip"`      //最后登录IP
	PwdUpdateTime  customtype.JsonTime `json:"pwd_update_time"`                   //密码最后修改时间
	Remarks        string              `gorm:"size:500" json:"remarks"`           //备注
}

func (AccessAccount) TableName() string {
	return "access_account"
}
