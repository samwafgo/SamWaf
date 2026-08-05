package model

import (
	"SamWaf/model/baseorm"
)

// 未认证时的响应方式
const (
	AccessUnauthAuto     = "auto"     // 自动判定：浏览器导航 302，API/WebSocket 401 JSON
	AccessUnauthRedirect = "redirect" // 一律 302
	AccessUnauth401      = "401"      // 一律 401 JSON
)

// 默认值。改这里等于改新装默认，改动前先确认不会让存量用户升级后行为突变。
const (
	AccessDefaultPathPrefix    = "/samwaf_access"
	AccessDefaultCookiePrefix  = "samwaf_ac"
	AccessDefaultSessionTTLMin = 720 // 12 小时
	AccessDefaultTokenTTLMin   = 720
	AccessDefaultTicketTTLSec  = 60
	AccessDefaultIdleMin       = 0 // 0=不启用空闲超时
	AccessDefaultMaxFail       = 10
	AccessDefaultLockMinutes   = 3
	AccessDefaultCachePosTTL   = 60 // 正向缓存上限(秒)，同时也是踢下线的最坏生效延迟
)

// AccessConfig 是统一访问认证的租户级全局配置，全表只有一行。
//
// 为什么不塞进 system_config（那张扁平 KV 表）：
//  1. HmacSecret 是密钥，必须 wafsec 加密落库，KV 表的 value 列是明文；
//  2. 字段太多，KV 表在管理端渲染出来会很难用；
//  3. 保存时要做联动校验（认证中心域名必须已在网站列表里配置过）。
//
// 唯一留在 system_config 的是总开关 access_enable → global.GCONFIG_ACCESS_ENABLE，
// 因为它需要能在管理端一键关掉自救，且走 TaskLoadSetting 每分钟自动刷新。
type AccessConfig struct {
	baseorm.BaseOrm

	// —— 认证中心 ——
	// 完整 origin（如 https://sso.example.com:8443），保存时必填：所有站点都先跳到它登录，
	// 登录一次即可访问全部受保护站点。该域名必须已经是 SamWaf 里配置过的站点，
	// 否则请求根本进不到引擎（ServeHTTP 找不到 host 直接 403）。
	// 为空只可能是「还没配过」或「认证中心站点被改了域名」，引擎此时放行并告警。
	CenterOrigin string `gorm:"size:255" json:"center_origin"`

	// —— 路径与 Cookie 命名（可随机化以隐藏系统指纹）——
	PathPrefix   string `gorm:"size:128" json:"path_prefix"`  //默认 /samwaf_access
	CookiePrefix string `gorm:"size:64" json:"cookie_prefix"` //默认 samwaf_ac
	HmacSecret   string `gorm:"size:512" json:"-"`            //rq 签名密钥，wafsec 加密存储，永不回显

	// —— 有效期 ——
	SessionTTLMinutes  int `json:"session_ttl_minutes"`  //中心会话绝对有效期
	TokenTTLMinutes    int `json:"token_ttl_minutes"`    //业务域子令牌有效期
	TicketTTLSeconds   int `json:"ticket_ttl_seconds"`   //跨域票据有效期，够一次 302 往返即可
	IdleTimeoutMinutes int `json:"idle_timeout_minutes"` //空闲多久自动失效，0=不启用

	// —— 安全强化 ——
	BindIP          int `json:"bind_ip"`          //1=令牌绑定签发时的IP，换IP立即失效（移动网络切换会掉线）
	BindFingerprint int `json:"bind_fingerprint"` //1=令牌绑定设备指纹
	RequireOtp      int `json:"require_otp"`      //1=全局要求二次验证，账号可用 ForceOtp 覆盖
	MaxFailCount    int `json:"max_fail_count"`   //登录失败上限（IP 与账号两个维度分别计数）
	LockMinutes     int `json:"lock_minutes"`     //触发上限后的锁定分钟数

	// —— 旁路（给健康检查、webhook 回调这类无法登录的调用方留的口子）——
	GlobalExcludePaths string `gorm:"type:text" json:"global_exclude_paths"` //免认证路径前缀，换行分隔
	BypassIPGroupCode  string `gorm:"size:64" json:"bypass_ip_group_code"`   //免认证 IP 组，复用 ip_group
	ServiceTokenHeader string `gorm:"size:64" json:"service_token_header"`   //服务令牌请求头名，如 X-Service-Token
	ServiceTokenHashes string `gorm:"type:text" json:"-"`                    //可用令牌的 sha256，换行分隔，永不回显

	// —— 行为 ——
	UnauthAction        string `gorm:"size:16" json:"unauth_action"` //auto | redirect | 401
	PassIdentityHeader  int    `json:"pass_identity_header"`         //1=向后端透传 X-SamWaf-Access-User
	ForceSecureCookie   int    `json:"force_secure_cookie"`          //1=强制 Secure（全站 HTTPS 时开）
	CachePositiveTTLSec int    `json:"cache_positive_ttl_sec"`       //正向缓存上限，同时是踢下线最坏延迟

	// 以下字段不落库，仅用于 API 回显“是否已设置”，避免前端把空值当成“未配置”而误清。
	HasHmacSecret   bool `gorm:"-" json:"has_hmac_secret"`
	HasServiceToken bool `gorm:"-" json:"has_service_token"`
}

func (AccessConfig) TableName() string {
	return "access_config"
}

// DefaultAccessConfig 返回一份「功能可用但足够保守」的默认配置。
//
// 注意这里没有 Enable 字段——总开关在 global.GCONFIG_ACCESS_ENABLE，默认 0（关闭）。
// 本结构体即使有值，只要总开关是关的且站点没设成强制开，就一个请求都不会被拦。
func DefaultAccessConfig() AccessConfig {
	return AccessConfig{
		PathPrefix:          AccessDefaultPathPrefix,
		CookiePrefix:        AccessDefaultCookiePrefix,
		SessionTTLMinutes:   AccessDefaultSessionTTLMin,
		TokenTTLMinutes:     AccessDefaultTokenTTLMin,
		TicketTTLSeconds:    AccessDefaultTicketTTLSec,
		IdleTimeoutMinutes:  AccessDefaultIdleMin,
		BindIP:              0,
		BindFingerprint:     0,
		RequireOtp:          0,
		MaxFailCount:        AccessDefaultMaxFail,
		LockMinutes:         AccessDefaultLockMinutes,
		UnauthAction:        AccessUnauthAuto,
		PassIdentityHeader:  0,
		ForceSecureCookie:   0,
		CachePositiveTTLSec: AccessDefaultCachePosTTL,
	}
}

// FillDefaults 把零值/越界字段补成默认值。
// 存量行缺字段、用户手工改库改出非法值时都靠它兜底，保证引擎侧永远拿到合法配置。
func (c *AccessConfig) FillDefaults() {
	d := DefaultAccessConfig()
	if c.PathPrefix == "" {
		c.PathPrefix = d.PathPrefix
	}
	if c.CookiePrefix == "" {
		c.CookiePrefix = d.CookiePrefix
	}
	if c.SessionTTLMinutes <= 0 {
		c.SessionTTLMinutes = d.SessionTTLMinutes
	}
	if c.TokenTTLMinutes <= 0 {
		c.TokenTTLMinutes = d.TokenTTLMinutes
	}
	if c.TicketTTLSeconds <= 0 || c.TicketTTLSeconds > 300 {
		c.TicketTTLSeconds = d.TicketTTLSeconds
	}
	if c.IdleTimeoutMinutes < 0 {
		c.IdleTimeoutMinutes = 0
	}
	if c.MaxFailCount <= 0 {
		c.MaxFailCount = d.MaxFailCount
	}
	if c.LockMinutes <= 0 {
		c.LockMinutes = d.LockMinutes
	}
	switch c.UnauthAction {
	case AccessUnauthAuto, AccessUnauthRedirect, AccessUnauth401:
	default:
		c.UnauthAction = d.UnauthAction
	}
	// 正向缓存上限直接决定踢下线的最坏生效延迟，不允许被放大到分钟级
	if c.CachePositiveTTLSec <= 0 || c.CachePositiveTTLSec > AccessDefaultCachePosTTL {
		c.CachePositiveTTLSec = d.CachePositiveTTLSec
	}
}
