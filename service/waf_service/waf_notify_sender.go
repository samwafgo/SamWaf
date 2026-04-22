package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/wafnotify/dingtalk"
	"SamWaf/wafnotify/email"
	"SamWaf/wafnotify/feishu"
	"SamWaf/wafnotify/serverchan"
	"SamWaf/wafnotify/wechatwork"
	"fmt"
	"strings"
	"sync"
)

type WafNotifySenderService struct{}

var WafNotifySenderServiceApp = new(WafNotifySenderService)

// SendNotification 发送通知
func (receiver *WafNotifySenderService) SendNotification(messageType, title, content string) {
	// 如果配置了通知标题前缀，则在标题前加上 [前缀] 以区分多实例
	if global.GWAF_NOTICE_TITLE != "" {
		title = "[" + global.GWAF_NOTICE_TITLE + "] " + title
	}

	// 获取订阅
	subscriptions := WafNotifySubscriptionServiceApp.GetSubscriptionsByMessageType(messageType)
	if len(subscriptions) == 0 {
		zlog.Debug(fmt.Sprintf("没有找到消息类型 %s 的订阅", messageType))
		return
	}

	// 使用 WaitGroup 和信号量控制并发，防止goroutine爆炸
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3) // 限制最多3个渠道并发发送

	// 遍历订阅，发送通知
	for _, subscription := range subscriptions {
		// 获取渠道信息
		var channel model.NotifyChannel
		err := receiver.getChannelById(subscription.ChannelId, &channel)
		if err != nil {
			zlog.Error(fmt.Sprintf("获取渠道信息失败: %v", err))
			continue
		}

		// 发送通知（传入subscription以支持订阅级收件人）
		wg.Add(1)
		sem <- struct{}{} // 获取信号量，超过3个会阻塞等待
		go func(ch model.NotifyChannel, sub model.NotifySubscription) {
			defer wg.Done()
			defer func() { <-sem }() // 释放信号量
			receiver.sendToChannel(ch, sub, messageType, title, content)
		}(channel, subscription)
	}

	wg.Wait() // 等待所有渠道发送完成
}

// getChannelById 根据ID获取渠道
func (receiver *WafNotifySenderService) getChannelById(channelId string, channel *model.NotifyChannel) error {
	return global.GWAF_LOCAL_DB.Where("id = ? and status = ?", channelId, 1).First(channel).Error
}

// sendToChannel 发送到具体渠道
func (receiver *WafNotifySenderService) sendToChannel(channel model.NotifyChannel, subscription model.NotifySubscription, messageType, title, content string) {
	var err error
	status := 1
	errorMsg := ""
	recipients := "" // 用于记录实际使用的收件人

	switch channel.Type {
	case "dingtalk":
		notifier := dingtalk.NewDingTalkNotifier(channel.WebhookURL, channel.Secret)
		err = notifier.SendMarkdown(title, content)
	case "feishu":
		notifier := feishu.NewFeishuNotifier(channel.WebhookURL, channel.Secret)
		err = notifier.SendMarkdown(title, content)
	case "wechatwork":
		notifier := wechatwork.NewWechatWorkNotifier(channel.WebhookURL)
		err = notifier.SendMarkdown(title, content)
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
	default:
		err = fmt.Errorf("不支持的通知类型: %s", channel.Type)
	}

	if err != nil {
		status = 0
		errorMsg = err.Error()
		zlog.Error(fmt.Sprintf("发送通知失败: %v", err))
	}

	// 记录日志
	logErr := WafNotifyLogServiceApp.AddLog(
		channel.Id,
		channel.Name,
		channel.Type,
		messageType,
		title,
		content,
		recipients, // 传递收件人信息
		status,
		errorMsg,
	)
	if logErr != nil {
		zlog.Error(fmt.Sprintf("记录通知日志失败: %v", logErr))
	}
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
