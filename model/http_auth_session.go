package model

import (
	"SamWaf/customtype"
	"SamWaf/model/baseorm"
)

// 会话状态
const (
	HttpAuthStatusRevoked = 0 // 已失效（被踢/到期）
	HttpAuthStatusValid   = 1 // 有效
)

// 认证方式，与 hosts.HttpAuthBaseType 取值一致
const (
	HttpAuthTypeAuthorization = "authorization" // 浏览器弹窗（HTTP Basic）
	HttpAuthTypeCustom        = "custom"        // 自定义登录页
)

// 会话失效原因（RevokeReason）
const (
	HttpAuthRevokeByAdmin   = "admin_kick"  // 管理端踢下线
	HttpAuthRevokeByExpire  = "expired"     // 到期，由清理任务标记
	HttpAuthRevokeByAccount = "account_off" // 账号被删除或改密
	HttpAuthRevokeByHost    = "host_off"    // 站点被删除或关闭了密码访问
)

// HttpAuthSession 是「网站密码访问」的一次登录，管理端据此展示在线列表并踢下线。
//
// TokenCode 存的是摘要而不是明文：
//   - custom 模式  = sha256hex(Cookie 明文)
//   - basic  模式  = sha256hex(hostCode|用户名|客户端IP)
//
// 前者与 access_session 同理——库被拖走也拿不到可直接使用的 Cookie，同时它正好能当缓存键后缀，
// 管理端在不知道明文的前提下就能精确驱逐某条会话的缓存。
// 后者是因为 HTTP Basic 没有令牌可言：浏览器每个请求原样重发凭证，服务端能识别的最小单位
// 就是「哪个用户从哪个 IP 来」，所以这三元组的摘要就是它的会话身份。
type HttpAuthSession struct {
	baseorm.BaseOrm
	HostCode       string              `gorm:"size:64;index" json:"host_code"`  //归属站点
	Host           string              `gorm:"size:255" json:"host"`            //冗余域名(含端口)，列表直接展示
	TokenCode      string              `gorm:"size:64;index" json:"token_code"` //见上方说明，存摘要不存明文
	AuthType       string              `gorm:"size:20" json:"auth_type"`        //authorization | custom
	UserName       string              `gorm:"size:255" json:"user_name"`
	ClientIP       string              `gorm:"size:64" json:"client_ip"`   //按站点「真实IP来源」解析出的访客 IP，与访问日志的 SRC_IP 同源
	Country        string              `gorm:"size:64" json:"country"`     //归属地-国家
	City           string              `gorm:"size:64" json:"city"`        //归属地-省市
	UserAgent      string              `gorm:"size:512" json:"user_agent"` //登录时的UA
	Status         int                 `json:"status"`                     //1有效 0已失效
	RevokeReason   string              `gorm:"size:128" json:"revoke_reason"`
	LoginTime      customtype.JsonTime `json:"login_time"`
	LastActiveTime customtype.JsonTime `json:"last_active_time"` //最后活跃时间（节流更新）
	ExpireTime     customtype.JsonTime `json:"expire_time"`      //绝对过期时间
	RemainSeconds  int64               `gorm:"-" json:"remain_seconds"`
}

func (HttpAuthSession) TableName() string {
	return "http_auth_session"
}
