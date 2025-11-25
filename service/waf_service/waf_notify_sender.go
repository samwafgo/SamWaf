package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/wafnotify/dingtalk"
	"SamWaf/wafnotify/feishu"
	"fmt"
)

type WafNotifySenderService struct{}

var WafNotifySenderServiceApp = new(WafNotifySenderService)

// SendNotification 发送通知
func (receiver *WafNotifySenderService) SendNotification(messageType, title, content string) {
	// 获取订阅
	subscriptions := WafNotifySubscriptionServiceApp.GetSubscriptionsByMessageType(messageType)
	if len(subscriptions) == 0 {
		zlog.Debug(fmt.Sprintf("没有找到消息类型 %s 的订阅", messageType))
		return
	}

	// 遍历订阅，发送通知
	for _, subscription := range subscriptions {
		// 获取渠道信息
		var channel model.NotifyChannel
		err := receiver.getChannelById(subscription.ChannelId, &channel)
		if err != nil {
			zlog.Error(fmt.Sprintf("获取渠道信息失败: %v", err))
			continue
		}

		// 发送通知
		go receiver.sendToChannel(channel, messageType, title, content)
	}
}

// getChannelById 根据ID获取渠道
func (receiver *WafNotifySenderService) getChannelById(channelId string, channel *model.NotifyChannel) error {
	return global.GWAF_LOCAL_DB.Where("id = ? and status = ?", channelId, 1).First(channel).Error
}

// sendToChannel 发送到具体渠道
func (receiver *WafNotifySenderService) sendToChannel(channel model.NotifyChannel, messageType, title, content string) {
	var err error
	status := 1
	errorMsg := ""

	switch channel.Type {
	case "dingtalk":
		notifier := dingtalk.NewDingTalkNotifier(channel.WebhookURL, channel.Secret)
		err = notifier.SendMarkdown(title, content)
	case "feishu":
		notifier := feishu.NewFeishuNotifier(channel.WebhookURL, channel.Secret)
		err = notifier.SendMarkdown(title, content)
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
func (receiver *WafNotifySenderService) FormatIPBanMessage(ip, reason, time string, duration int) (string, string) {
	title := "IP封禁通知"
	content := fmt.Sprintf("**IP地址:** %s\n\n**封禁原因:** %s\n\n**封禁时长:** %d分钟\n\n**封禁时间:** %s", ip, reason, duration, time)
	return title, content
}
