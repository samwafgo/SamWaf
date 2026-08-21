package request

import "SamWaf/model/common/request"

// ─────────────── 访问账号 ───────────────

type WafAccessAccountAddReq struct {
	AccountName    string `json:"account_name" binding:"required"`
	Password       string `json:"password" binding:"required"`
	NickName       string `json:"nick_name"`
	Status         int    `json:"status"`
	ForceOtp       int    `json:"force_otp"`        //0继承全局 1强制 2豁免
	AllowHostCodes string `json:"allow_host_codes"` //换行分隔；空=全部站点
	ExpireTime     string `json:"expire_time"`      //yyyy-MM-dd HH:mm:ss，空=永不过期
	Remarks        string `json:"remarks"`
}

type WafAccessAccountEditReq struct {
	Id             string `json:"id" binding:"required"`
	NickName       string `json:"nick_name"`
	Status         int    `json:"status"`
	ForceOtp       int    `json:"force_otp"`
	AllowHostCodes string `json:"allow_host_codes"`
	ExpireTime     string `json:"expire_time"`
	Remarks        string `json:"remarks"`
}

// WafAccessAccountResetPwdReq 重置密码。
// 登录名不可改（它是会话与审计的关联键），所以改密走独立接口而不是塞进 Edit。
type WafAccessAccountResetPwdReq struct {
	Id       string `json:"id" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type WafAccessAccountDetailReq struct {
	Id string `json:"id" form:"id"`
}

type WafAccessAccountDelReq struct {
	Id string `json:"id" form:"id"`
}

type WafAccessAccountSearchReq struct {
	AccountName string `json:"account_name"`
	Status      *int   `json:"status"` //指针：不传=全部，传 0 才能查到已禁用账号
	request.PageInfo
}

type WafAccessAccountOtpInitReq struct {
	Id string `json:"id" form:"id"`
}

type WafAccessAccountOtpBindReq struct {
	Id     string `json:"id" binding:"required"`
	Secret string `json:"secret" binding:"required"`
	Code   string `json:"code" binding:"required"`
}

type WafAccessAccountOtpUnbindReq struct {
	Id string `json:"id" binding:"required"`
}

// ─────────────── 全局配置 ───────────────

type WafAccessConfigSaveReq struct {
	CenterOrigin string `json:"center_origin"` //认证中心完整地址，必填
	PathPrefix   string `json:"path_prefix"`
	CookiePrefix string `json:"cookie_prefix"`

	SessionTTLMinutes  int `json:"session_ttl_minutes"`
	TokenTTLMinutes    int `json:"token_ttl_minutes"`
	TicketTTLSeconds   int `json:"ticket_ttl_seconds"`
	IdleTimeoutMinutes int `json:"idle_timeout_minutes"`

	BindIP          int `json:"bind_ip"`
	BindFingerprint int `json:"bind_fingerprint"`
	RequireOtp      int `json:"require_otp"`
	MaxFailCount    int `json:"max_fail_count"`
	LockMinutes     int `json:"lock_minutes"`

	GlobalExcludePaths string `json:"global_exclude_paths"`
	BypassIPGroupCode  string `json:"bypass_ip_group_code"`
	ServiceTokenHeader string `json:"service_token_header"`
	// ServiceTokens 是明文服务令牌，后端只存 sha256。
	// 空字符串 = 保持原样不动；填 "-" = 清空。这样前端不必回显密文也能安全编辑。
	ServiceTokens string `json:"service_tokens"`

	UnauthAction        string `json:"unauth_action"`
	PassIdentityHeader  int    `json:"pass_identity_header"`
	ForceSecureCookie   int    `json:"force_secure_cookie"`
	CachePositiveTTLSec int    `json:"cache_positive_ttl_sec"`
}

// ─────────────── 会话 ───────────────

type WafAccessSessionSearchReq struct {
	AccountName string `json:"account_name"`
	ClientIP    string `json:"client_ip"`
	Status      *int   `json:"status"`
	request.PageInfo
}

type WafAccessSessionKickReq struct {
	Id string `json:"id" form:"id"`
}

type WafAccessSessionKickByAccountReq struct {
	AccountId string `json:"account_id" form:"account_id"`
}

// ─────────────── 审计日志 ───────────────

type WafAccessAuditSearchReq struct {
	Category    string `json:"category"` //审计分类 access/config，空=全部
	Event       string `json:"event"`
	AccountName string `json:"account_name"`
	ClientIP    string `json:"client_ip"`
	Host        string `json:"host"`
	StartDay    int    `json:"start_day"` //20260801
	EndDay      int    `json:"end_day"`
	request.PageInfo
}
