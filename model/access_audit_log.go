package model

import (
	"SamWaf/model/baseorm"
)

// 审计事件类型
const (
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
)

// 审计结果
const (
	AccessAuditFail = 0
	AccessAuditOK   = 1
)

// AccessEventNames 事件的中文名，通知正文用。
// 与上面的常量放在一起，是为了新增事件时一眼看到还有这张表要补。
var AccessEventNames = map[string]string{
	AccessEventLoginOK:       "登录成功",
	AccessEventLoginFail:     "密码错误",
	AccessEventOtpFail:       "动态码错误",
	AccessEventLocked:        "登录失败次数超限，已锁定",
	AccessEventLogout:        "主动注销",
	AccessEventKick:          "管理端踢下线",
	AccessEventTicketIssue:   "签发跨站点票据",
	AccessEventTicketConsume: "票据兑换成功",
	AccessEventTicketReplay:  "票据重放或伪造",
	AccessEventBadReturnTo:   "回跳地址异常，疑似开放重定向攻击",
	AccessEventDenied:        "未认证访问被拦截",
	AccessEventBypassIP:      "命中免认证IP组放行",
	AccessEventBypassToken:   "命中服务令牌放行",
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
}

// AccessAuditLog 是统一访问认证的结构化安全事件流水。
//
// 为什么不复用 web_logs：web_logs 是「每请求一条」的高频流水，字段是围绕攻击检测设计的，
// 按账号/事件类型检索很别扭。本表只记低频的安全语义事件（登录、踢人、票据异常），
// 唯一的高频事件 denied 在写入侧做了「同 IP+同域名 5 分钟一条」的节流，
// 否则一次目录扫描就能把表刷爆。
//
// 表放 log 库（migrations_log.go）而不是 core 库：与 account_logs 同属审计流水，
// 生命周期一致；且 wafdb/log_shard.go 的分库只搬 web_logs 一张表，本表不受影响。
type AccessAuditLog struct {
	baseorm.BaseOrm
	Event       string `gorm:"size:32" json:"event"` //见上方 AccessEvent* 常量
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

func (AccessAuditLog) TableName() string {
	return "access_audit_log"
}
