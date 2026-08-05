package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/wafdb/dialect"
	"SamWaf/wafnotify/dingtalk"
	"SamWaf/wafnotify/email"
	"SamWaf/wafnotify/feishu"
	"SamWaf/wafnotify/serverchan"
	"SamWaf/wafnotify/webhook"
	"SamWaf/wafnotify/wechatwork"
	"fmt"
	"strings"
	"sync"
	"time"
)

// buildWebhookMessage 组装通用 Webhook 的模板变量
//
// 只给「标题/正文 + 几个公共维度」：更细的字段（域名、攻击IP…）由订阅级模板渲染进正文，
// 两层模板各管一段，不在渠道层重复一遍变量表。
func buildWebhookMessage(messageType, title, content string) webhook.Message {
	return webhook.Message{
		Title:           title,
		Content:         content,
		Time:            time.Now().Format("2006-01-02 15:04:05"),
		MessageType:     messageType,
		MessageTypeName: GetMessageTypeName(messageType),
		Severity:        GetMessageTypeSeverity(messageType),
		ServerName:      global.GWAF_CUSTOM_SERVER_NAME,
	}
}

type WafNotifySenderService struct{}

var WafNotifySenderServiceApp = new(WafNotifySenderService)

// SendMessageInfo 通知发送主入口：把队列里的消息结构走完整的「结构化→频控→模板→渠道」链路
func (receiver *WafNotifySenderService) SendMessageInfo(messageInfo interface{}) {
	ev := receiver.BuildNotifyEvent(messageInfo)
	if ev.MessageType == "" {
		zlog.Debug("未识别的通知消息结构，已忽略")
		return
	}
	receiver.SendEvent(ev)
}

// SendEvent 按订阅逐个判定并投递
//
// 频控在这里逐订阅判定（而不是像老实现那样在入队前一刀切），
// 这样钉钉和飞书可以有完全不同的节奏，且频控 key 不再是可被 payload 变换绕过的规则原文。
func (receiver *WafNotifySenderService) SendEvent(ev NotifyEvent) {
	if ev.MessageType == "" {
		return
	}

	subscriptions := WafNotifySubscriptionServiceApp.GetSubscriptionsByMessageType(ev.MessageType)
	if len(subscriptions) == 0 {
		zlog.Debug(fmt.Sprintf("没有找到消息类型 %s 的订阅", ev.MessageType))
		return
	}

	// 使用 WaitGroup 和信号量控制并发，防止goroutine爆炸
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3) // 限制最多3个渠道并发发送

	for _, subscription := range subscriptions {
		var channel model.NotifyChannel
		err := receiver.getChannelById(subscription.ChannelId, &channel)
		if err != nil {
			zlog.Error(fmt.Sprintf("获取渠道信息失败: %v", err))
			continue
		}

		decision := WafNotifyThrottleServiceApp.Decide(subscription, ev)
		switch decision.Action {
		case ThrottleActionSuppress:
			// 被频控/过滤挡下：不发送，但要留痕，否则用户永远查不到"为什么没收到"
			receiver.logSuppressed(subscription, channel, ev, decision)

		case ThrottleActionAggregate:
			NotifyAggregatorApp.Add(subscription, channel, ev, decision)

		default: // send
			wg.Add(1)
			sem <- struct{}{}
			go func(ch model.NotifyChannel, sub model.NotifySubscription, dedupKey string) {
				defer wg.Done()
				defer func() { <-sem }()
				receiver.DispatchEvents(sub, ch, []NotifyEvent{ev}, dedupKey, decision.Effective.AggregateMaxDetail)
			}(channel, subscription, decision.DedupKey)
		}
	}

	wg.Wait() // 等待所有渠道发送完成
}

// DispatchEvents 渲染并投递（单条或聚合后的多条）
//
// 聚合器刷新时也走这里，保证"直发"和"聚合发"共用同一套渲染、前缀、日志逻辑。
func (receiver *WafNotifySenderService) DispatchEvents(sub model.NotifySubscription, channel model.NotifyChannel,
	events []NotifyEvent, dedupKey string, maxDetail int) {
	if len(events) == 0 {
		return
	}

	// 结算本次发送之前被压掉的条数：既要写进正文告诉用户"其实发生了很多次"，
	// 也要回填到那条抑制日志上，让通知日志页显示准确的抑制总数。
	suppressLogID, suppressedCount := WafNotifyThrottleServiceApp.NoteSent(dedupKey)

	title, content, templateUsed := BuildMergedMessage(sub, channel.Type, events, maxDetail)
	if suppressedCount > 0 {
		content += fmt.Sprintf("\n\n> 期间另有 %d 条同类通知被频率控制抑制", suppressedCount)
	}

	// 如果配置了通知标题前缀，则在标题前加上 [前缀] 以区分多实例
	if global.GWAF_NOTICE_TITLE != "" {
		title = "[" + global.GWAF_NOTICE_TITLE + "] " + title
	}

	receiver.sendToChannel(channel, sub, events[0].MessageType, title, content, templateUsed)

	if suppressLogID != "" && suppressedCount > 0 {
		if err := WafNotifyLogServiceApp.UpdateSuppressCount(suppressLogID, suppressedCount); err != nil {
			zlog.Debug("回填抑制条数失败", "error", err.Error())
		}
	}
}

// SendNotification 发送通知（兼容入口：只有标题正文、没有结构化变量的调用方仍可使用）
func (receiver *WafNotifySenderService) SendNotification(messageType, title, content string) {
	ev := newNotifyEvent(messageType, title, content)
	receiver.SendEvent(ev)
}

// logSuppressed 记录一条被抑制的通知
//
// 关键约束：抑制日志本身不能刷库。写不写由频控引擎决定（一个抑制窗口只写一条），
// 压掉一万条也只会产生 2 次数据库写入。
func (receiver *WafNotifySenderService) logSuppressed(sub model.NotifySubscription, channel model.NotifyChannel,
	ev NotifyEvent, decision ThrottleDecision) {
	action := WafNotifyThrottleServiceApp.OnSuppress(decision.DedupKey)

	if action.FinalizeLogID != "" && action.FinalizeCount > 0 {
		if err := WafNotifyLogServiceApp.UpdateSuppressCount(action.FinalizeLogID, action.FinalizeCount); err != nil {
			zlog.Debug("回填抑制条数失败", "error", err.Error())
		}
	}
	if !action.WriteNew {
		return
	}

	logID, err := WafNotifyLogServiceApp.AddSuppressLog(model.NotifyLog{
		ChannelId:      channel.Id,
		ChannelName:    channel.Name,
		ChannelType:    channel.Type,
		MessageType:    ev.MessageType,
		MessageTitle:   ev.DefaultTitle,
		MessageContent: ev.DefaultContent,
		SubscriptionId: sub.Id,
		SuppressReason: decision.Reason,
		SuppressCount:  1,
	})
	if err != nil {
		zlog.Debug("记录抑制日志失败", "error", err.Error())
		return
	}
	WafNotifyThrottleServiceApp.SetSuppressLogID(decision.DedupKey, logID)
}

// getChannelById 根据ID获取渠道
func (receiver *WafNotifySenderService) getChannelById(channelId string, channel *model.NotifyChannel) error {
	return global.GWAF_LOCAL_DB.Where("id = ? and "+dialect.Q("status")+" = ?", channelId, 1).First(channel).Error
}

// sendToChannel 发送到具体渠道并记录日志
func (receiver *WafNotifySenderService) sendToChannel(channel model.NotifyChannel, subscription model.NotifySubscription, messageType, title, content, templateUsed string) {
	recipients, err := receiver.deliverToChannel(channel, subscription, messageType, title, content)

	status := 1
	errorMsg := ""
	if err != nil {
		status = 0
		errorMsg = err.Error()
		zlog.Error(fmt.Sprintf("发送通知失败: %v", err))
	}

	// 记录日志
	_, logErr := WafNotifyLogServiceApp.AddLogDetail(model.NotifyLog{
		ChannelId:      channel.Id,
		ChannelName:    channel.Name,
		ChannelType:    channel.Type,
		MessageType:    messageType,
		MessageTitle:   title,
		MessageContent: content,
		Recipients:     recipients, // 传递收件人信息
		Status:         status,
		ErrorMsg:       errorMsg,
		SubscriptionId: subscription.Id,
		TemplateUsed:   templateUsed,
	})
	if logErr != nil {
		zlog.Error(fmt.Sprintf("记录通知日志失败: %v", logErr))
	}
}

// deliverToChannel 只负责把消息投递到渠道，返回实际收件人与错误
//
// 从 sendToChannel 里拆出来，是为了让「订阅级测试发送」能拿到真实错误反馈给管理端 ——
// issue #822 的标题就是"通知管理无法调试"，测试发送必须走完全相同的投递链路。
func (receiver *WafNotifySenderService) deliverToChannel(channel model.NotifyChannel,
	subscription model.NotifySubscription, messageType, title, content string) (recipients string, err error) {
	switch channel.Type {
	case "dingtalk":
		if ok, reason := utils.IsSafeOutboundURL(channel.WebhookURL); !ok {
			err = fmt.Errorf("WebhookURL 目标不被允许: %s", reason)
		} else {
			notifier := dingtalk.NewDingTalkNotifier(channel.WebhookURL, channel.Secret)
			err = notifier.SendMarkdown(title, content)
		}
	case "feishu":
		if ok, reason := utils.IsSafeOutboundURL(channel.WebhookURL); !ok {
			err = fmt.Errorf("WebhookURL 目标不被允许: %s", reason)
		} else {
			notifier := feishu.NewFeishuNotifier(channel.WebhookURL, channel.Secret)
			err = notifier.SendMarkdown(title, content)
		}
	case "wechatwork":
		if ok, reason := utils.IsSafeOutboundURL(channel.WebhookURL); !ok {
			err = fmt.Errorf("WebhookURL 目标不被允许: %s", reason)
		} else {
			notifier := wechatwork.NewWechatWorkNotifier(channel.WebhookURL)
			err = notifier.SendMarkdown(title, content)
		}
	case "email":
		notifier, notifierErr := email.NewEmailNotifier(channel.ConfigJSON)
		if notifierErr != nil {
			err = notifierErr
		} else {
			// 关键：支持订阅级别的收件人配置（向后兼容）
			if subscription.Recipients != "" {
				// 优先使用订阅中配置的收件人
				recipientList := strings.Split(subscription.Recipients, ",")
				var trimmedRecipients []string
				for _, r := range recipientList {
					trimmed := strings.TrimSpace(r)
					if trimmed != "" {
						trimmedRecipients = append(trimmedRecipients, trimmed)
					}
				}
				if len(trimmedRecipients) > 0 {
					notifier.SetRecipients(trimmedRecipients)
					recipients = strings.Join(trimmedRecipients, ", ") // 记录实际收件人
				}
			} else {
				// 使用渠道默认收件人（从notifier获取）
				recipients = strings.Join(notifier.ToEmails, ", ")
			}
			// 如果订阅中没有配置收件人，则使用渠道配置中的收件人（向后兼容）
			err = notifier.SendMarkdown(title, content)
		}
	case "serverchan":
		notifier, notifierErr := serverchan.NewServerChanNotifier(channel.AccessToken)
		if notifierErr != nil {
			err = notifierErr
		} else {
			err = notifier.SendMarkdown(title, content)
		}
	case "webhook":
		// 地址/方法/请求头/报文模板全在 ConfigJSON 里，SSRF 校验在 notifier 内部做（构造与发送各一次）
		notifier, notifierErr := webhook.NewWebhookNotifier(channel.ConfigJSON)
		if notifierErr != nil {
			err = notifierErr
		} else {
			err = notifier.Send(buildWebhookMessage(messageType, title, content))
		}
	default:
		err = fmt.Errorf("不支持的通知类型: %s", channel.Type)
	}
	return recipients, err
}

// SendTestToSubscription 订阅级测试发送
//
// 用样例数据 + 当前（可能尚未保存的）模板走真实投递链路，绕过频控与过滤 ——
// 调试时用户要看的就是"这条通知发出去到底长什么样"，被频控挡住反而更困惑。
func (receiver *WafNotifySenderService) SendTestToSubscription(sub model.NotifySubscription,
	channel model.NotifyChannel, titleTemplate, contentTemplate string) error {
	ev := SampleNotifyEvent(sub.MessageType)

	// 用传入的模板覆盖库里的，这样"编辑中还没保存"也能测
	testSub := sub
	testSub.TitleTemplate = titleTemplate
	testSub.ContentTemplate = contentTemplate

	title, content, templateUsed := RenderNotifyMessage(testSub, channel.Type, ev)
	title = "【测试】" + title
	if global.GWAF_NOTICE_TITLE != "" {
		title = "[" + global.GWAF_NOTICE_TITLE + "] " + title
	}
	content += "\n\n> 本条为通知订阅测试消息，不代表真实事件"

	recipients, err := receiver.deliverToChannel(channel, testSub, sub.MessageType, title, content)

	status := 1
	errorMsg := ""
	if err != nil {
		status = 0
		errorMsg = err.Error()
	}
	if _, logErr := WafNotifyLogServiceApp.AddLogDetail(model.NotifyLog{
		ChannelId:      channel.Id,
		ChannelName:    channel.Name,
		ChannelType:    channel.Type,
		MessageType:    sub.MessageType,
		MessageTitle:   title,
		MessageContent: content,
		Recipients:     recipients,
		Status:         status,
		ErrorMsg:       errorMsg,
		SubscriptionId: sub.Id,
		TemplateUsed:   templateUsed,
	}); logErr != nil {
		zlog.Debug("记录测试通知日志失败", "error", logErr.Error())
	}
	return err
}

// FormatUserLoginMessage 格式化用户登录消息
func (receiver *WafNotifySenderService) FormatUserLoginMessage(username, ip, time string) (string, string) {
	title := "用户登录通知"
	content := fmt.Sprintf("**用户:** %s\n\n**IP地址:** %s\n\n**登录时间:** %s", username, ip, time)
	return title, content
}

// FormatAttackInfoMessage 格式化攻击信息消息
func (receiver *WafNotifySenderService) FormatAttackInfoMessage(attackType, url, ip, time string) (string, string) {
	title := "攻击告警通知"
	content := fmt.Sprintf("**攻击类型:** %s\n\n**URL:** %s\n\n**攻击IP:** %s\n\n**攻击时间:** %s", attackType, url, ip, time)
	return title, content
}

// FormatWeeklyReportMessage 格式化周报消息
func (receiver *WafNotifySenderService) FormatWeeklyReportMessage(totalRequests, blockedRequests int64, weekRange string) (string, string) {
	title := "WAF周报"
	content := fmt.Sprintf("**周期:** %s\n\n**总请求数:** %d\n\n**拦截请求数:** %d\n\n**拦截率:** %.2f%%",
		weekRange,
		totalRequests,
		blockedRequests,
		float64(blockedRequests)/float64(totalRequests)*100)
	return title, content
}

// FormatSSLExpireMessage 格式化SSL证书过期消息
func (receiver *WafNotifySenderService) FormatSSLExpireMessage(domain string, expireTime string, daysLeft int) (string, string) {
	title := "SSL证书即将过期通知"
	content := fmt.Sprintf("**域名:** %s\n\n**过期时间:** %s\n\n**剩余天数:** %d天", domain, expireTime, daysLeft)
	return title, content
}

// FormatSystemErrorMessage 格式化系统错误消息
func (receiver *WafNotifySenderService) FormatSystemErrorMessage(errorType, errorMsg, time string) (string, string) {
	title := "系统错误通知"
	content := fmt.Sprintf("**错误类型:** %s\n\n**错误信息:** %s\n\n**发生时间:** %s", errorType, errorMsg, time)
	return title, content
}

// FormatIPBanMessage 格式化IP封禁消息
func (receiver *WafNotifySenderService) FormatIPBanMessage(ip, reason, time string, duration int, remainingSeconds int) (string, string) {
	title := "IP封禁通知"
	var remainingStr string
	if remainingSeconds <= 0 {
		remainingStr = "已过期"
	} else if remainingSeconds < 60 {
		remainingStr = fmt.Sprintf("%d秒", remainingSeconds)
	} else {
		remainingStr = fmt.Sprintf("%d分%d秒", remainingSeconds/60, remainingSeconds%60)
	}
	content := fmt.Sprintf("**IP地址:** %s\n\n**封禁原因:** %s\n\n**封禁时长:** %d分钟\n\n**剩余时间:** %s\n\n**封禁时间:** %s", ip, reason, duration, remainingStr, time)
	return title, content
}

// ========== 消息映射方法：将旧消息结构转换为新格式 ==========

// FormatMessageByType 根据消息类型格式化消息（统一入口）
func (receiver *WafNotifySenderService) FormatMessageByType(messageInfo interface{}) (messageType, title, content string) {
	switch msg := messageInfo.(type) {
	case innerbean.RuleMessageInfo:
		return receiver.FormatRuleMessage(msg)
	case innerbean.OperatorMessageInfo:
		return receiver.FormatOperatorMessage(msg)
	case innerbean.UserLoginMessageInfo:
		return receiver.FormatUserLoginMessageFromBean(msg)
	case innerbean.AttackInfoMessageInfo:
		return receiver.FormatAttackInfoMessageFromBean(msg)
	case innerbean.WeeklyReportMessageInfo:
		return receiver.FormatWeeklyReportMessageFromBean(msg)
	case innerbean.SSLExpireMessageInfo:
		return receiver.FormatSSLExpireMessageFromBean(msg)
	case innerbean.SystemErrorMessageInfo:
		return receiver.FormatSystemErrorMessageFromBean(msg)
	case innerbean.IPBanMessageInfo:
		return receiver.FormatIPBanMessageFromBean(msg)
	case innerbean.AccessMessageInfo:
		return receiver.FormatAccessMessageFromBean(msg)
	default:
		return "", "", ""
	}
}

// FormatRuleMessage 格式化规则触发消息（映射旧的 RuleMessageInfo）
func (receiver *WafNotifySenderService) FormatRuleMessage(msg innerbean.RuleMessageInfo) (string, string, string) {
	messageType := "rule_trigger" // 规则触发类型
	title := "安全规则触发通知"
	content := fmt.Sprintf("**操作类型:** %s\n\n**服务器:** %s\n\n**域名:** %s\n\n**规则信息:** %s\n\n**IP地址:** %s",
		msg.OperaType,
		msg.Server,
		msg.Domain,
		msg.RuleInfo,
		msg.Ip)
	return messageType, title, content
}

// FormatOperatorMessage 格式化操作消息（映射旧的 OperatorMessageInfo）
func (receiver *WafNotifySenderService) FormatOperatorMessage(msg innerbean.OperatorMessageInfo) (string, string, string) {
	messageType := "operation_notice" // 操作通知类型
	title := "操作通知"
	content := fmt.Sprintf("**操作类型:** %s\n\n**服务器:** %s\n\n**操作内容:** %s",
		msg.OperaType,
		msg.Server,
		msg.OperaCnt)
	return messageType, title, content
}

// FormatUserLoginMessageFromBean 格式化用户登录消息（从Bean）
func (receiver *WafNotifySenderService) FormatUserLoginMessageFromBean(msg innerbean.UserLoginMessageInfo) (string, string, string) {
	messageType := "user_login" // 用户登录类型
	title, content := receiver.FormatUserLoginMessage(msg.Username, msg.Ip, msg.Time)
	return messageType, title, content
}

// FormatAccessMessageFromBean 格式化统一访问认证事件（从Bean）
//
// 登录成功与异常告警走两个不同的 messageType：用户可以只订阅告警而不被日常登录打扰。
// 正文里把「账号 + 域名 + IP + 归属地」都摆出来 —— 收到告警的人第一反应就是
// 「谁、从哪儿、动了哪个站」，缺一样就得回管理端翻审计日志。
func (receiver *WafNotifySenderService) FormatAccessMessageFromBean(msg innerbean.AccessMessageInfo) (string, string, string) {
	messageType := model.MSG_TYPE_ACCESS_LOGIN
	title := "统一访问认证登录通知"
	if msg.Abnormal {
		messageType = model.MSG_TYPE_ACCESS_ABNORMAL
		title = "统一访问认证异常告警"
	}

	account := msg.AccountName
	if account == "" {
		account = "-"
	}
	location := msg.Location
	if strings.TrimSpace(location) == "" {
		location = "未知"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "**事件:** %s\n\n**账号:** %s\n\n**来源IP:** %s\n\n**归属地:** %s",
		msg.EventName, account, msg.Ip, location)
	if msg.Host != "" {
		fmt.Fprintf(&b, "\n\n**访问域名:** %s", msg.Host)
	}
	if msg.Url != "" {
		fmt.Fprintf(&b, "\n\n**访问地址:** %s", msg.Url)
	}
	if msg.Message != "" {
		fmt.Fprintf(&b, "\n\n**详情:** %s", msg.Message)
	}
	fmt.Fprintf(&b, "\n\n**时间:** %s", msg.Time)
	return messageType, title, b.String()
}

// FormatAttackInfoMessageFromBean 格式化攻击信息消息（从Bean）
func (receiver *WafNotifySenderService) FormatAttackInfoMessageFromBean(msg innerbean.AttackInfoMessageInfo) (string, string, string) {
	messageType := "attack_info" // 攻击信息类型
	title, content := receiver.FormatAttackInfoMessage(msg.AttackType, msg.Url, msg.Ip, msg.Time)
	return messageType, title, content
}

// FormatWeeklyReportMessageFromBean 格式化周报消息（从Bean）
func (receiver *WafNotifySenderService) FormatWeeklyReportMessageFromBean(msg innerbean.WeeklyReportMessageInfo) (string, string, string) {
	messageType := "weekly_report" // 周报类型
	title, content := receiver.FormatWeeklyReportMessage(msg.TotalRequests, msg.BlockedRequests, msg.WeekRange)
	return messageType, title, content
}

// FormatSSLExpireMessageFromBean 格式化SSL证书过期消息（从Bean）
func (receiver *WafNotifySenderService) FormatSSLExpireMessageFromBean(msg innerbean.SSLExpireMessageInfo) (string, string, string) {
	messageType := "ssl_expire" // SSL证书过期类型
	title, content := receiver.FormatSSLExpireMessage(msg.Domain, msg.ExpireTime, msg.DaysLeft)
	return messageType, title, content
}

// FormatSystemErrorMessageFromBean 格式化系统错误消息（从Bean）
func (receiver *WafNotifySenderService) FormatSystemErrorMessageFromBean(msg innerbean.SystemErrorMessageInfo) (string, string, string) {
	messageType := "system_error" // 系统错误类型
	title, content := receiver.FormatSystemErrorMessage(msg.ErrorType, msg.ErrorMsg, msg.Time)
	return messageType, title, content
}

// FormatIPBanMessageFromBean 格式化IP封禁消息（从Bean）
func (receiver *WafNotifySenderService) FormatIPBanMessageFromBean(msg innerbean.IPBanMessageInfo) (string, string, string) {
	messageType := "ip_ban" // IP封禁类型
	title, content := receiver.FormatIPBanMessage(msg.Ip, msg.Reason, msg.Time, msg.Duration, msg.RemainingSeconds)
	return messageType, title, content
}
