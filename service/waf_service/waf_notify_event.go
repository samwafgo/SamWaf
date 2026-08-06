package waf_service

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"strconv"
	"strings"
	"time"
)

/*
*
通知事件结构化（issue #822）

老实现里 FormatXxxMessage 直接吐一段拼好的字符串，模板引擎拿不到任何变量，频控也拿不到
「域名/IP/攻击类型」这些去重维度。这里补一层结构化事件：

  - Vars       给模板引擎用
  - DedupParts 给频控算 key 用
  - Default*   仍旧复用原来的 FormatXxxMessage，一个字都没改，
    所以不配模板的用户收到的内容与升级前逐字一致。
*/

// NotifyEvent 结构化通知事件
type NotifyEvent struct {
	MessageType     string            // 消息类型（model.MSG_TYPE_*）
	MessageTypeName string            // 消息类型中文名
	Severity        string            // 严重级别 info/warn/critical
	Time            time.Time         // 事件时间
	Vars            map[string]string // 模板变量
	DedupParts      map[string]string // 去重维度取值（domain/ip/rule/attack_type）
	DefaultTitle    string            // 内置默认标题
	DefaultContent  string            // 内置默认正文
}

// notifyMessageTypeName 消息类型中文名
var notifyMessageTypeName = map[string]string{
	model.MSG_TYPE_RULE_TRIGGER:     "规则触发",
	model.MSG_TYPE_OPERATION_NOTICE: "操作通知",
	model.MSG_TYPE_USER_LOGIN:       "用户登录",
	model.MSG_TYPE_ATTACK_INFO:      "攻击信息",
	model.MSG_TYPE_WEEKLY_REPORT:    "周报",
	model.MSG_TYPE_SSL_EXPIRE:       "SSL证书过期",
	model.MSG_TYPE_SYSTEM_ERROR:     "系统错误",
	model.MSG_TYPE_IP_BAN:           "IP封禁",
	model.MSG_TYPE_ACCESS_LOGIN:     "统一访问认证-登录成功",
	model.MSG_TYPE_ACCESS_ABNORMAL:  "统一访问认证-异常告警",

	model.MSG_TYPE_MANAGE_LOGIN_ABNORMAL: "管理端登录-来源变化",
}

// notifyMessageTypeSeverity 消息类型默认严重级别
//
// 级别只影响「过滤条件的最低级别」和「免打扰穿透」，不影响是否发送，
// 所以就算划分不完全贴合某个用户的认知，也不会导致漏告警。
var notifyMessageTypeSeverity = map[string]string{
	model.MSG_TYPE_RULE_TRIGGER:     model.SeverityWarn,
	model.MSG_TYPE_OPERATION_NOTICE: model.SeverityInfo,
	model.MSG_TYPE_USER_LOGIN:       model.SeverityInfo,
	model.MSG_TYPE_ATTACK_INFO:      model.SeverityCritical,
	model.MSG_TYPE_WEEKLY_REPORT:    model.SeverityInfo,
	model.MSG_TYPE_SSL_EXPIRE:       model.SeverityWarn,
	model.MSG_TYPE_SYSTEM_ERROR:     model.SeverityCritical,
	model.MSG_TYPE_IP_BAN:           model.SeverityWarn,
	model.MSG_TYPE_ACCESS_LOGIN:     model.SeverityInfo,
	model.MSG_TYPE_ACCESS_ABNORMAL:  model.SeverityCritical,

	model.MSG_TYPE_MANAGE_LOGIN_ABNORMAL: model.SeverityCritical,
}

// GetMessageTypeName 取消息类型中文名
func GetMessageTypeName(messageType string) string {
	if name, ok := notifyMessageTypeName[messageType]; ok {
		return name
	}
	return messageType
}

// GetMessageTypeSeverity 取消息类型默认严重级别
func GetMessageTypeSeverity(messageType string) string {
	if s, ok := notifyMessageTypeSeverity[messageType]; ok {
		return s
	}
	return model.SeverityInfo
}

// IsKnownMessageType 是否是已知消息类型（api 层入参白名单）
func IsKnownMessageType(messageType string) bool {
	_, ok := notifyMessageTypeName[messageType]
	return ok
}

// AllMessageTypes 全部消息类型（供前端下拉与批量配置使用）
func AllMessageTypes() []string {
	return []string{
		model.MSG_TYPE_USER_LOGIN,
		model.MSG_TYPE_RULE_TRIGGER,
		model.MSG_TYPE_IP_BAN,
		model.MSG_TYPE_ATTACK_INFO,
		model.MSG_TYPE_SSL_EXPIRE,
		model.MSG_TYPE_WEEKLY_REPORT,
		model.MSG_TYPE_SYSTEM_ERROR,
		model.MSG_TYPE_OPERATION_NOTICE,
		model.MSG_TYPE_ACCESS_LOGIN,
		model.MSG_TYPE_ACCESS_ABNORMAL,
		model.MSG_TYPE_MANAGE_LOGIN_ABNORMAL,
	}
}

// newNotifyEvent 构造事件骨架，填上公共变量
func newNotifyEvent(messageType, title, content string) NotifyEvent {
	now := time.Now()
	ev := NotifyEvent{
		MessageType:     messageType,
		MessageTypeName: GetMessageTypeName(messageType),
		Severity:        GetMessageTypeSeverity(messageType),
		Time:            now,
		Vars:            map[string]string{},
		DedupParts:      map[string]string{model.DedupKeyMessageType: messageType},
		DefaultTitle:    title,
		DefaultContent:  content,
	}
	ev.Vars["Time"] = now.Format("2006-01-02 15:04:05")
	ev.Vars["ServerName"] = global.GWAF_CUSTOM_SERVER_NAME
	ev.Vars["MessageType"] = messageType
	ev.Vars["MessageTypeName"] = ev.MessageTypeName
	ev.Vars["Severity"] = ev.Severity
	return ev
}

// BuildNotifyEvent 把队列里的消息结构转成结构化事件
//
// 默认标题/正文直接复用既有 FormatXxxMessage，避免两套格式化实现产生分叉。
func (receiver *WafNotifySenderService) BuildNotifyEvent(messageInfo interface{}) NotifyEvent {
	switch msg := messageInfo.(type) {
	case innerbean.RuleMessageInfo:
		mt, title, content := receiver.FormatRuleMessage(msg)
		ev := newNotifyEvent(mt, title, content)
		ev.Vars["OperaType"] = msg.OperaType
		ev.Vars["Server"] = msg.Server
		ev.Vars["Domain"] = msg.Domain
		ev.Vars["RuleInfo"] = msg.RuleInfo
		ev.Vars["Ip"] = msg.Ip
		ev.DedupParts[model.DedupKeyDomain] = msg.Domain
		ev.DedupParts[model.DedupKeyIp] = msg.Ip
		ev.DedupParts[model.DedupKeyRule] = msg.RuleInfo
		ev.DedupParts[model.DedupKeyAttackType] = msg.OperaType
		return ev

	case innerbean.OperatorMessageInfo:
		mt, title, content := receiver.FormatOperatorMessage(msg)
		ev := newNotifyEvent(mt, title, content)
		ev.Vars["OperaType"] = msg.OperaType
		ev.Vars["Server"] = msg.Server
		ev.Vars["OperaCnt"] = msg.OperaCnt
		ev.DedupParts[model.DedupKeyAttackType] = msg.OperaType
		return ev

	case innerbean.UserLoginMessageInfo:
		mt, title, content := receiver.FormatUserLoginMessageFromBean(msg)
		ev := newNotifyEvent(mt, title, content)
		ev.Vars["Username"] = msg.Username
		ev.Vars["Ip"] = msg.Ip
		ev.Vars["Server"] = msg.Server
		if msg.Time != "" {
			ev.Vars["Time"] = msg.Time
		}
		if msg.Abnormal {
			ev.Vars["LastIp"] = msg.LastIp
			ev.Vars["LastLocation"] = msg.LastLocation
			ev.Vars["LastTime"] = msg.LastTime
		}
		ev.DedupParts[model.DedupKeyIp] = msg.Ip
		return ev

	case innerbean.AttackInfoMessageInfo:
		mt, title, content := receiver.FormatAttackInfoMessageFromBean(msg)
		ev := newNotifyEvent(mt, title, content)
		ev.Vars["AttackType"] = msg.AttackType
		ev.Vars["Url"] = msg.Url
		ev.Vars["Ip"] = msg.Ip
		ev.Vars["Server"] = msg.Server
		if msg.Time != "" {
			ev.Vars["Time"] = msg.Time
		}
		ev.DedupParts[model.DedupKeyIp] = msg.Ip
		ev.DedupParts[model.DedupKeyAttackType] = msg.AttackType
		ev.DedupParts[model.DedupKeyDomain] = extractHostFromUrl(msg.Url)
		return ev

	case innerbean.WeeklyReportMessageInfo:
		mt, title, content := receiver.FormatWeeklyReportMessageFromBean(msg)
		ev := newNotifyEvent(mt, title, content)
		ev.Vars["TotalRequests"] = strconv.FormatInt(msg.TotalRequests, 10)
		ev.Vars["BlockedRequests"] = strconv.FormatInt(msg.BlockedRequests, 10)
		ev.Vars["BlockRate"] = formatBlockRate(msg.TotalRequests, msg.BlockedRequests)
		ev.Vars["WeekRange"] = msg.WeekRange
		return ev

	case innerbean.SSLExpireMessageInfo:
		mt, title, content := receiver.FormatSSLExpireMessageFromBean(msg)
		ev := newNotifyEvent(mt, title, content)
		ev.Vars["Domain"] = msg.Domain
		ev.Vars["ExpireTime"] = msg.ExpireTime
		ev.Vars["DaysLeft"] = strconv.Itoa(msg.DaysLeft)
		ev.DedupParts[model.DedupKeyDomain] = msg.Domain
		return ev

	case innerbean.SystemErrorMessageInfo:
		mt, title, content := receiver.FormatSystemErrorMessageFromBean(msg)
		ev := newNotifyEvent(mt, title, content)
		ev.Vars["ErrorType"] = msg.ErrorType
		ev.Vars["ErrorMsg"] = msg.ErrorMsg
		if msg.Time != "" {
			ev.Vars["Time"] = msg.Time
		}
		ev.DedupParts[model.DedupKeyAttackType] = msg.ErrorType
		return ev

	case innerbean.IPBanMessageInfo:
		mt, title, content := receiver.FormatIPBanMessageFromBean(msg)
		ev := newNotifyEvent(mt, title, content)
		ev.Vars["Ip"] = msg.Ip
		ev.Vars["Reason"] = msg.Reason
		ev.Vars["Duration"] = strconv.Itoa(msg.Duration)
		ev.Vars["Remaining"] = formatRemaining(msg.RemainingSeconds)
		if msg.Time != "" {
			ev.Vars["Time"] = msg.Time
		}
		ev.DedupParts[model.DedupKeyIp] = msg.Ip
		ev.DedupParts[model.DedupKeyAttackType] = msg.Reason
		return ev

	case innerbean.AccessMessageInfo:
		mt, title, content := receiver.FormatAccessMessageFromBean(msg)
		ev := newNotifyEvent(mt, title, content)
		ev.Vars["EventName"] = msg.EventName
		ev.Vars["AccountName"] = msg.AccountName
		ev.Vars["Host"] = msg.Host
		ev.Vars["Url"] = msg.Url
		ev.Vars["Ip"] = msg.Ip
		ev.Vars["Location"] = msg.Location
		ev.Vars["Message"] = msg.Message
		if msg.Time != "" {
			ev.Vars["Time"] = msg.Time
		}
		ev.DedupParts[model.DedupKeyDomain] = msg.Host
		ev.DedupParts[model.DedupKeyIp] = msg.Ip
		ev.DedupParts[model.DedupKeyAttackType] = msg.Event
		return ev
	}
	return NotifyEvent{}
}

// formatBlockRate 计算拦截率，总数为 0 时不做除法（老实现会出 NaN）
func formatBlockRate(total, blocked int64) string {
	if total <= 0 {
		return "0.00%"
	}
	return strconv.FormatFloat(float64(blocked)/float64(total)*100, 'f', 2, 64) + "%"
}

// formatRemaining 剩余封禁时间的可读表示，与 FormatIPBanMessage 保持一致
func formatRemaining(remainingSeconds int) string {
	if remainingSeconds <= 0 {
		return "已过期"
	}
	if remainingSeconds < 60 {
		return strconv.Itoa(remainingSeconds) + "秒"
	}
	return strconv.Itoa(remainingSeconds/60) + "分" + strconv.Itoa(remainingSeconds%60) + "秒"
}

// extractHostFromUrl 从攻击URL里粗提域名，供去重维度使用
//
// 不用 net/url.Parse：攻击URL经常是畸形串（正是它被拦下来的原因），Parse 失败率高且开销更大。
// 这里只做字符串切分，取不到就返回空串，频控会自动忽略空维度。
func extractHostFromUrl(rawUrl string) string {
	s := rawUrl
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	for _, sep := range []byte{'/', '?', ':'} {
		if idx := strings.IndexByte(s, sep); idx >= 0 {
			s = s[:idx]
		}
	}
	if len(s) > 253 { // 域名最大长度，防畸形超长串进缓存key
		return ""
	}
	return s
}
