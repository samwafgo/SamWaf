package model

import (
	"SamWaf/model/baseorm"
)

// 审计分类：access_audit_log 已升级为「统一安全审计流水」security_audit_log，
// 用 Category 区分不同来源的安全事件，前端可分类筛选，将来所有安全日志都汇到这张表。
const (
	AuditCategoryAccess   = "access"   //访问认证类（登录/踢人/票据/未认证拦截等）
	AuditCategoryConfig   = "config"   //敏感配置变更类（SSL 证书导出落盘等）
	AuditCategoryHttpAuth = "httpauth" //网站密码访问类（站点级 Basic/自定义登录页）
)

// 审计事件类型
const (
	// access 类：统一访问认证
	AccessEventLoginOK       = "login_ok"       //登录成功
	AccessEventLoginFail     = "login_fail"     //密码错误
	AccessEventOtpFail       = "otp_fail"       //动态码错误
	AccessEventLocked        = "locked"         //触发失败锁定
	AccessEventLogout        = "logout"         //主动注销
	AccessEventKick          = "kick"           //管理端踢下线
	AccessEventTicketIssue   = "ticket_issue"   //签发跨域票据
	AccessEventTicketConsume = "ticket_consume" //票据兑换成功
	AccessEventTicketReplay  = "ticket_replay"  //票据重放/伪造/过期，安全告警级
	AccessEventBadReturnTo   = "bad_return_to"  //回跳地址校验失败，疑似开放重定向攻击
	AccessEventDenied        = "denied"         //未认证被拦（高频，已节流）
	AccessEventBypassIP      = "bypass_ip"      //命中免认证IP组放行
	AccessEventBypassToken   = "bypass_token"   //命中服务令牌头放行

	// config 类：敏感配置变更（config_ 前缀，为将来敏感操作预留命名空间）
	AuditEventConfigSSLExportWrite = "config_ssl_export_write" //SSL 证书/私钥导出落盘（result 1成功 0失败/被拒）
	AuditEventConfigBatchTaskRun   = "config_batch_task_run"   //批量任务执行：读宿主机文件/拉远端地址并批量写防护策略（result 1成功 0失败/被拒）
	AuditEventConfigDiagPackage    = "config_diag_package"     //运行诊断包生成下载（result 1成功 0失败）

	// httpauth 类：网站密码访问。刻意与上面 access 类的同名事件分开命名空间，
	// 两者是各自独立开关、各自一套账号的功能，混进同一分类会让按分类筛选失去意义。
	HttpAuthEventLoginOK   = "httpauth_login_ok"   //网站密码登录成功
	HttpAuthEventLoginFail = "httpauth_login_fail" //网站密码错误
	HttpAuthEventLocked    = "httpauth_locked"     //登录失败超限，IP 被锁定
	HttpAuthEventKick      = "httpauth_kick"       //管理端踢下线
	HttpAuthEventExpired   = "httpauth_expired"    //会话到期，由清理任务按次汇总
	HttpAuthEventDenied    = "httpauth_denied"     //未登录被拦（高频，走 WriteThrottled）
)

// auditEventCategory 事件 → 分类映射。未登记的事件默认归 access（历史事件全是 access 类）。
var auditEventCategory = map[string]string{
	AuditEventConfigSSLExportWrite: AuditCategoryConfig,
	AuditEventConfigBatchTaskRun:   AuditCategoryConfig,
	AuditEventConfigDiagPackage:    AuditCategoryConfig,
	HttpAuthEventLoginOK:           AuditCategoryHttpAuth,
	HttpAuthEventLoginFail:         AuditCategoryHttpAuth,
	HttpAuthEventLocked:            AuditCategoryHttpAuth,
	HttpAuthEventKick:              AuditCategoryHttpAuth,
	HttpAuthEventExpired:           AuditCategoryHttpAuth,
	HttpAuthEventDenied:            AuditCategoryHttpAuth,
}

// AuditEventCategory 取事件所属分类，未知事件回退 access。
func AuditEventCategory(event string) string {
	if c, ok := auditEventCategory[event]; ok {
		return c
	}
	return AuditCategoryAccess
}

// 审计结果
const (
	AccessAuditFail = 0
	AccessAuditOK   = 1
)

// AccessEventNames 事件的中文名，通知正文用。
// 与上面的常量放在一起，是为了新增事件时一眼看到还有这张表要补。
var AccessEventNames = map[string]string{
	AccessEventLoginOK:             "登录成功",
	AccessEventLoginFail:           "密码错误",
	AccessEventOtpFail:             "动态码错误",
	AccessEventLocked:              "登录失败次数超限，已锁定",
	AccessEventLogout:              "主动注销",
	AccessEventKick:                "管理端踢下线",
	AccessEventTicketIssue:         "签发跨站点票据",
	AccessEventTicketConsume:       "票据兑换成功",
	AccessEventTicketReplay:        "票据重放或伪造",
	AccessEventBadReturnTo:         "回跳地址异常，疑似开放重定向攻击",
	AccessEventDenied:              "未认证访问被拦截",
	AccessEventBypassIP:            "命中免认证IP组放行",
	AccessEventBypassToken:         "命中服务令牌放行",
	AuditEventConfigSSLExportWrite: "SSL证书导出落盘",
	AuditEventConfigBatchTaskRun:   "批量任务执行",
	AuditEventConfigDiagPackage:    "运行诊断包下载",
	HttpAuthEventLoginOK:           "网站密码登录成功",
	HttpAuthEventLoginFail:         "网站密码错误",
	HttpAuthEventLocked:            "网站密码失败超限，已锁定",
	HttpAuthEventKick:              "网站密码会话被踢下线",
	HttpAuthEventExpired:           "网站密码会话到期",
	HttpAuthEventDenied:            "未登录访问被拦截",
}

// AccessEventName 取事件中文名，未知事件回退成原始事件码而不是空串。
func AccessEventName(event string) string {
	if name, ok := AccessEventNames[event]; ok {
		return name
	}
	return event
}

// AccessNotifyEvents 决定哪些审计事件要往外发通知，值为「是否属于异常告警」。
//
// 登录成功与异常告警是两个独立的订阅类型：绝大多数人只想被安全事件打扰，
// 而不是每有人登录一次就收到一条消息。混在一起会逼用户二选一。
//
// 刻意不发通知的事件及理由：
//   - login_fail / otp_fail：单次输错太常见，连续错会触发 locked，由 locked 代表
//   - denied：一次目录扫描就是几千条，发通知等于自我 DDoS
//   - bypass_* / ticket_issue / ticket_consume / logout / kick：正常流程噪声
var AccessNotifyEvents = map[string]bool{
	AccessEventLoginOK:      false,
	AccessEventLocked:       true,
	AccessEventTicketReplay: true,
	AccessEventBadReturnTo:  true,
	// 网站密码访问只挑锁定这一件事发通知，理由与上面 access 侧逐条一致：
	// 登录成功属正常流程、单次密码错误太常见（连续错会走到 locked）、未登录拦截是高频事件。
	HttpAuthEventLocked: true,
}

// SecurityAuditLog 是统一访问认证的结构化安全事件流水。
//
// 为什么不复用 web_logs：web_logs 是「每请求一条」的高频流水，字段是围绕攻击检测设计的，
// 按账号/事件类型检索很别扭。本表只记低频的安全语义事件（登录、踢人、票据异常），
// 唯一的高频事件 denied 在写入侧做了「同 IP+同域名 5 分钟一条」的节流，
// 否则一次目录扫描就能把表刷爆。
//
// 表放 log 库（migrations_log.go）而不是 core 库：与 account_logs 同属审计流水，
// 生命周期一致；且 wafdb/log_shard.go 的分库只搬 web_logs 一张表，本表不受影响。
type SecurityAuditLog struct {
	baseorm.BaseOrm
	Category    string `gorm:"size:16;index" json:"category"` //审计分类 access/config，见 AuditCategory* 常量
	Event       string `gorm:"size:32" json:"event"`          //见上方 AccessEvent* / AuditEventConfig* 常量
	AccountName string `gorm:"size:128" json:"account_name"`
	SessionCode string `gorm:"size:64" json:"session_code"`
	Host        string `gorm:"size:255" json:"host"`
	HostCode    string `gorm:"size:64" json:"host_code"`
	URL         string `gorm:"type:text" json:"url"`
	ClientIP    string `gorm:"size:64" json:"client_ip"`
	Country     string `gorm:"size:64" json:"country"`
	City        string `gorm:"size:64" json:"city"`
	UserAgent   string `gorm:"size:512" json:"user_agent"`
	Fingerprint string `gorm:"size:64" json:"fingerprint"`
	Result      int    `json:"result"`                  //1成功 0失败
	Message     string `gorm:"size:500" json:"message"` //人类可读说明，不得含密码/令牌明文
	Day         int    `json:"day"`                     //20260804，按天清理与按天统计都靠它
}

func (SecurityAuditLog) TableName() string {
	return "security_audit_log"
}
