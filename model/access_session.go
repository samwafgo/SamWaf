package model

import (
	"SamWaf/customtype"
	"SamWaf/model/baseorm"
)

// 会话/令牌状态
const (
	AccessStatusRevoked = 0 // 已注销/被踢
	AccessStatusValid   = 1 // 有效
)

// 会话作用域
const (
	AccessScopeSSO = "sso" // 一次登录换取多个业务域的子令牌，这是现在唯一会被创建的作用域
	// AccessScopeLocal 是早期「每域各自登录」方案留下的作用域，已不再签发。
	// 常量与 loadValidSession 里的 BindHost 校验都保留着：升级前建的老会话若还在库里，
	// 必须继续按"只服务一个域名"来判，不能因为不认识就当成全站通行。
	AccessScopeLocal = "local"
)

// 会话被撤销的原因（RevokeReason）
const (
	AccessRevokeByAdmin   = "admin_kick"  // 管理端踢下线
	AccessRevokeByLogout  = "logout"      // 用户主动注销
	AccessRevokeByExpire  = "expired"     // 到期被清理任务标记
	AccessRevokeByAccount = "account_off" // 账号被禁用/删除
)

// AccessSession 是中心会话，代表「这个人已经登录了」。
//
// SessionCode 存的是 Cookie 明文的 sha256 十六进制摘要，不是明文本身：
// 这样即使数据库被拖走，攻击者也拿不到可直接使用的 Cookie。
// 同样的道理，它也正好可以当缓存键的后缀——管理端在不知道明文的前提下
// 就能精确驱逐某个会话的缓存条目（见 waf_access_session_service.go 的踢下线）。
type AccessSession struct {
	baseorm.BaseOrm
	SessionCode    string              `gorm:"size:64" json:"session_code"`   //sha256hex(cookie明文)，唯一
	AccountCode    string              `gorm:"size:64" json:"account_code"`   //AccessAccount.Id
	AccountName    string              `gorm:"size:128" json:"account_name"`  //冗余登录名，方便列表展示与审计
	Scope          string              `gorm:"size:16" json:"scope"`          //sso | local
	BindHost       string              `gorm:"size:255" json:"bind_host"`     //scope=local 时绑定的域名
	ClientIP       string              `gorm:"size:64" json:"client_ip"`      //登录时的客户端IP
	Fingerprint    string              `gorm:"size:64" json:"fingerprint"`    //登录时的设备指纹
	UserAgent      string              `gorm:"size:512" json:"user_agent"`    //登录时的UA
	Country        string              `gorm:"size:64" json:"country"`        //归属地-国家
	City           string              `gorm:"size:64" json:"city"`           //归属地-城市
	Status         int                 `json:"status"`                        //1有效 0已注销/被踢
	RevokeReason   string              `gorm:"size:128" json:"revoke_reason"` //撤销原因
	LoginTime      customtype.JsonTime `json:"login_time"`                    //登录时间
	LastActiveTime customtype.JsonTime `json:"last_active_time"`              //最后活跃时间（节流更新，见 idle_timeout）
	ExpireTime     customtype.JsonTime `json:"expire_time"`                   //绝对过期时间
	TokenCount     int                 `gorm:"-" json:"token_count"`          //关联子令牌数，列表接口聚合填充，不落库
	TokenHosts     []string            `gorm:"-" json:"token_hosts"`          //已登站点的域名列表，与 TokenCount 一起填充。光给数量看不出影响面，管理员真正想知道的是"他进了哪几个站"
}

func (AccessSession) TableName() string {
	return "access_session"
}

// AccessToken 是某个业务域名上的子令牌，代表「这个人在 app.example.com 上已认证」。
//
// 它永远从属于一个 AccessSession：中心会话被踢，所有子令牌一并失效
// （校验时 JOIN 会话表判 status/expire_time，不是靠级联删除）。
// 这正是「一处登出、处处失效」得以成立的原因。
type AccessToken struct {
	baseorm.BaseOrm
	TokenCode      string              `gorm:"size:64" json:"token_code"`   //sha256hex(cookie明文)，唯一
	SessionCode    string              `gorm:"size:64" json:"session_code"` //所属中心会话
	AccountName    string              `gorm:"size:128" json:"account_name"`
	Host           string              `gorm:"size:255" json:"host"`       //生效域名（含端口，与请求的 r.Host 比对）
	HostCode       string              `gorm:"size:64" json:"host_code"`   //站点唯一码
	ClientIP       string              `gorm:"size:64" json:"client_ip"`   //签发时的客户端IP（bind_ip 开启时校验）
	Fingerprint    string              `gorm:"size:64" json:"fingerprint"` //签发时的设备指纹（bind_fingerprint 开启时校验）
	Status         int                 `json:"status"`
	LastActiveTime customtype.JsonTime `json:"last_active_time"`
	ExpireTime     customtype.JsonTime `json:"expire_time"` //= min(会话过期时间, now+token_ttl)
}

func (AccessToken) TableName() string {
	return "access_token"
}
