package model

import (
	"SamWaf/model/baseorm"
)

/*
*
通知订阅配置
*/
type NotifySubscription struct {
	baseorm.BaseOrm
	ChannelId   string `gorm:"size:64" json:"channel_id"`    // 关联的渠道ID
	MessageType string `gorm:"size:100" json:"message_type"` // 消息类型：user_login, attack_info, weekly_report等
	Recipients  string `gorm:"type:text" json:"recipients"`  // 收件人列表（逗号分隔，主要用于邮件类型）留空则使用渠道默认收件人
	Status      int    `json:"status"`                       // 状态：1启用，0禁用
	FilterJSON  string `gorm:"type:text" json:"filter_json"` // 过滤条件（JSON格式，见 NotifyFilterConfig）
	Remarks     string `gorm:"size:500" json:"remarks"`      // 备注

	// ===== 频率控制（issue #822）=====
	// 默认 inherit + 空 JSON，等价于升级前的固定行为；用户不配置就什么都不变。
	ThrottleMode string `gorm:"size:20" json:"throttle_mode"`   // 频控模式：inherit/realtime/aggregate/cooldown
	ThrottleJSON string `gorm:"type:text" json:"throttle_json"` // 频控细项（JSON格式，见 NotifyThrottleConfig）

	// ===== 消息模板（issue #822）=====
	// 留空则使用内置默认格式，渲染失败也会自动降级回内置格式，保证告警不会因为模板写错而丢失。
	TitleTemplate   string `gorm:"size:500" json:"title_template"`    // 自定义标题模板
	ContentTemplate string `gorm:"type:text" json:"content_template"` // 自定义正文模板
}

// GetThrottleConfig 取解析后的频控配置
func (s NotifySubscription) GetThrottleConfig() NotifyThrottleConfig {
	return ParseNotifyThrottleConfig(s.ThrottleJSON)
}

// GetFilterConfig 取解析后的过滤条件
func (s NotifySubscription) GetFilterConfig() NotifyFilterConfig {
	return ParseNotifyFilterConfig(s.FilterJSON)
}

// 消息类型常量
const (
	MSG_TYPE_RULE_TRIGGER     = "rule_trigger"     // 规则触发
	MSG_TYPE_OPERATION_NOTICE = "operation_notice" // 操作通知
	MSG_TYPE_USER_LOGIN       = "user_login"       // 用户登录
	MSG_TYPE_ATTACK_INFO      = "attack_info"      // 攻击信息
	MSG_TYPE_WEEKLY_REPORT    = "weekly_report"    // 周报
	MSG_TYPE_SSL_EXPIRE       = "ssl_expire"       // SSL证书过期
	MSG_TYPE_SYSTEM_ERROR     = "system_error"     // 系统错误
	MSG_TYPE_IP_BAN           = "ip_ban"           // IP封禁
	// 统一访问认证刻意拆成两个类型：登录成功是日常告知，异常是安全告警。
	// 合成一个的话，只想收告警的人会被每一次正常登录打扰，最后干脆退订，告警也就收不到了。
	MSG_TYPE_ACCESS_LOGIN    = "access_login"    // 统一访问认证-登录成功
	MSG_TYPE_ACCESS_ABNORMAL = "access_abnormal" // 统一访问认证-异常告警
	// 管理端登录来源变化：同理和 user_login 拆开，日常登录归 user_login，
	// 换 IP/换归属地这种「可能是别人登进来了」的事件单独一类，方便只订阅它。
	MSG_TYPE_MANAGE_LOGIN_ABNORMAL = "manage_login_abnormal" // 管理端登录-来源变化告警
)
