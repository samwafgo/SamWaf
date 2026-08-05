package wafqueue

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafsec"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

/*
*
处理消息队列信息
*/
func ProcessMessageDequeEngine() {
	// 启动通知聚合器定时刷新（在时间窗口内按消息类型合并通知，避免通知轰炸）
	go gNotifyAgg.StartFlushLoop()

	for {
		select {
		case <-global.GWAF_QUEUE_SHUTDOWN_SIGNAL:
			zlog.Info("消息队列处理协程收到关闭信号，正在退出...")
			return
		default:
			for !global.GQEQUE_MESSAGE_DB.Empty() {
				popFront, ok := global.GQEQUE_MESSAGE_DB.Dequeue()
				if !ok {
					zlog.Error("来得信息未空")
					continue
				}

				// 处理不同类型的消息
				switch msg := popFront.(type) {
				case innerbean.RuleMessageInfo:
					handleRuleMessage(msg)
				case innerbean.OperatorMessageInfo:
					handleOperatorMessage(msg)
				case innerbean.UserLoginMessageInfo:
					handleUserLoginMessage(msg)
				case innerbean.AttackInfoMessageInfo:
					handleAttackInfoMessage(msg)
				case innerbean.WeeklyReportMessageInfo:
					handleWeeklyReportMessage(msg)
				case innerbean.SSLExpireMessageInfo:
					handleSSLExpireMessage(msg)
				case innerbean.SystemErrorMessageInfo:
					handleSystemErrorMessage(msg)
				case innerbean.IPBanMessageInfo:
					handleIPBanMessage(msg)
				case innerbean.AccessMessageInfo:
					handleAccessMessage(msg)
				case innerbean.ExportResultMessageInfo:
					exportResult := msg
					//发送websocket
					for _, ws := range global.GWebSocket.GetAllWebSocket() {
						if ws != nil {
							//信息包体进行单独处理
							msgBody, _ := json.Marshal(model.MsgDataPacket{
								MessageId:           uuid.GenUUID(),
								MessageType:         "导出结果",
								MessageData:         exportResult.Msg,
								MessageAttach:       nil,
								MessageDateTime:     time.Now().Format("2006-01-02 15:04:05"),
								MessageUnReadStatus: true,
							})
							encryptStr, _ := wafsec.AesEncrypt(msgBody, global.GWAF_COMMUNICATION_KEY)
							//写入ws数据
							msgBytes, err := json.Marshal(model.MsgPacket{
								MsgCode:       "200",
								MsgDataPacket: encryptStr,
								MsgCmdType:    "DOWNLOAD_LOG",
							})
							err = ws.WriteMessage(1, msgBytes)
							if err != nil {
								zlog.Info("发送websocket错误", err)
								continue
							}
						}
					}
				case innerbean.UpdateResultMessageInfo:
					//升级结果
					updatemessage := msg
					//发送websocket
					for _, ws := range global.GWebSocket.GetAllWebSocket() {
						if ws != nil {
							//信息包体进行单独处理
							msgBody, _ := json.Marshal(model.MsgDataPacket{
								MessageId:           uuid.GenUUID(),
								MessageType:         "升级结果",
								MessageData:         updatemessage.Msg,
								MessageAttach:       nil,
								MessageDateTime:     time.Now().Format("2006-01-02 15:04:05"),
								MessageUnReadStatus: true,
							})
							encryptStr, _ := wafsec.AesEncrypt(msgBody, global.GWAF_COMMUNICATION_KEY)
							//写入ws数据
							msgBytes, err := json.Marshal(model.MsgPacket{
								MsgCode:       "200",
								MsgDataPacket: encryptStr,
								MsgCmdType:    "Info",
							})
							err = ws.WriteMessage(1, msgBytes)
							if err != nil {
								zlog.Info("发送websocket错误", err)
								continue
							}
						}
					}
				case innerbean.OpResultMessageInfo:
					//操作实时结果
					updatemessage := msg
					//发送websocket
					for _, ws := range global.GWebSocket.GetAllWebSocket() {
						if ws != nil {
							//信息包体进行单独处理
							msgBody, _ := json.Marshal(model.MsgDataPacket{
								MessageId:           uuid.GenUUID(),
								MessageType:         "信息通知",
								MessageData:         updatemessage.Msg,
								MessageAttach:       nil,
								MessageDateTime:     time.Now().Format("2006-01-02 15:04:05"),
								MessageUnReadStatus: true,
							})
							encryptStr, _ := wafsec.AesEncrypt(msgBody, global.GWAF_COMMUNICATION_KEY)
							//写入ws数据
							msgBytes, err := json.Marshal(model.MsgPacket{
								MsgCode:       "200",
								MsgDataPacket: encryptStr,
								MsgCmdType:    "Info",
							})
							err = ws.WriteMessage(1, msgBytes)
							if err != nil {
								zlog.Info("发送websocket错误", err)
								continue
							}
						}
					}
				case innerbean.SystemStatsData:
					statsData := msg
					//发送websocket
					for _, ws := range global.GWebSocket.GetAllWebSocket() {
						if ws != nil {
							//信息包体进行单独处理
							msgBody, _ := json.Marshal(model.MsgDataPacket{
								MessageId:           uuid.GenUUID(),
								MessageType:         "系统统计信息",
								MessageData:         "",
								MessageAttach:       statsData,
								MessageDateTime:     time.Now().Format("2006-01-02 15:04:05"),
								MessageUnReadStatus: true,
							})
							encryptStr, _ := wafsec.AesEncrypt(msgBody, global.GWAF_COMMUNICATION_KEY)
							//写入ws数据
							msgBytes, err := json.Marshal(model.MsgPacket{
								MsgCode:       "200",
								MsgDataPacket: encryptStr,
								MsgCmdType:    "SystemStats",
							})
							err = ws.WriteMessage(1, msgBytes)
							if err != nil {
								zlog.Info("发送websocket错误", err)
								continue
							}
						}
					}
				}

			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// ========== 通知频率抑制（递增冷却策略） ==========
//
// 策略说明（参考 Prometheus AlertManager 的 group_interval 思路）：
//   - 首次出现：立即发送
//   - 发送后进入冷却期，冷却期内同规则通知被抑制
//   - 冷却时间逐级递增：1分钟 → 5分钟 → 15分钟（封顶）
//   - 30分钟内无新通知则冷却级别自动重置，恢复灵敏度
//
// 通知时间线示例（持续攻击场景）：
//   T=0s    → 首次攻击，立即通知，冷却1min
//   T=1min  → 冷却结束，仍有攻击则通知，冷却5min
//   T=6min  → 冷却结束，仍有攻击则通知，冷却15min
//   T=21min → 冷却结束，仍有攻击则通知，保持15min冷却
//   ...
//   攻击停止30min → 冷却级别归零，下次攻击从1min冷却重新开始

// notifyCooldownIntervals 冷却时间梯度
var notifyCooldownIntervals = []time.Duration{
	1 * time.Minute,  // Level 0: 首次发送后冷却1分钟
	5 * time.Minute,  // Level 1: 第二次发送后冷却5分钟
	15 * time.Minute, // Level 2+: 之后每次冷却15分钟（封顶）
}

// getCooldownDuration 根据冷却级别获取对应的冷却时间
func getCooldownDuration(level int) time.Duration {
	if level < 0 {
		level = 0
	}
	if level >= len(notifyCooldownIntervals) {
		return notifyCooldownIntervals[len(notifyCooldownIntervals)-1]
	}
	return notifyCooldownIntervals[level]
}

// checkCanSend 通知频率抑制：基于递增冷却策略判断是否允许发送
func checkCanSend(key string) bool {
	// SSL证书相关的消息（包括申请和续期）都直接发送，不受频率限制
	if strings.HasPrefix(key, "SSL证书") {
		return true
	}

	cooldownKey := enums.CACHE_NOTICE_PRE + key
	levelKey := enums.CACHE_NOTICE_PRE + key + "_lv"

	// 冷却期内 → 直接抑制
	if global.GCACHE_WAFCACHE.IsKeyExist(cooldownKey) {
		return false
	}

	// 冷却期已过（或首次出现）→ 允许发送
	// 获取当前冷却级别（key不存在时默认为0）
	level := 0
	if lv, err := global.GCACHE_WAFCACHE.GetInt(levelKey); err == nil {
		level = lv
	}

	// 根据冷却级别确定本次冷却时长
	cooldownDuration := getCooldownDuration(level)

	// 设置冷却标记（使用 RenewTime 确保从当前时刻开始计时）
	global.GCACHE_WAFCACHE.SetWithTTlRenewTime(cooldownKey, 1, cooldownDuration)

	// 提升冷却级别（30分钟无新通知则自动重置到初始级别，恢复灵敏度）
	global.GCACHE_WAFCACHE.SetWithTTlRenewTime(levelKey, level+1, 30*time.Minute)

	zlog.Debug(fmt.Sprintf("通知频率控制: key=%s, level=%d, cooldown=%v", key, level, cooldownDuration))

	return true
}

// ========== 各类消息处理函数（保持队列+WebSocket方式，集成新的通知系统） ==========

// handleRuleMessage 处理规则触发消息
func handleRuleMessage(msg innerbean.RuleMessageInfo) {
	isCanSend := checkCanSend(msg.RuleInfo)
	if !isCanSend {
		return
	}

	// 1. 加入通知聚合器（定时合并发送，避免通知轰炸）
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatRuleMessage(msg)
	gNotifyAgg.Add(notifyEntry{MessageType: messageType, Title: title, Content: content})

	// 2. 保留原有的通知方式（兼容旧系统）
	if global.GWAF_NOTICE_ENABLE {
		utils.NotifyHelperApp.SendRuleInfo(msg)
	} else {
		zlog.Debug("通知关闭状态")
	}

	// 3. 发送到 WebSocket（实时推送，不走聚合）
	if msg.BaseMessageInfo.OperaType == "命中保护规则" {
		sendToWebSocket("命中保护规则", msg.RuleInfo+msg.Ip, nil, "Info")
	}
}

// handleOperatorMessage 处理操作消息
func handleOperatorMessage(msg innerbean.OperatorMessageInfo) {
	isCanSend := checkCanSend(msg.OperaType)
	if !isCanSend {
		return
	}

	// 1. 加入通知聚合器
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatOperatorMessage(msg)
	gNotifyAgg.Add(notifyEntry{MessageType: messageType, Title: title, Content: content})

	// 2. 保留原有的通知方式
	utils.NotifyHelperApp.SendNoticeInfo(msg)

	// 3. 发送到 WebSocket（实时推送）
	sendToWebSocket(msg.OperaType, msg.OperaCnt, nil, "Info")
}

// handleUserLoginMessage 处理用户登录消息
func handleUserLoginMessage(msg innerbean.UserLoginMessageInfo) {
	// 1. 发送到新的通知订阅系统
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatUserLoginMessageFromBean(msg)
	waf_service.WafNotifySenderServiceApp.SendNotification(messageType, title, content)

	// 2. 发送到 WebSocket
	wsContent := fmt.Sprintf("用户 %s 从 %s 登录", msg.Username, msg.Ip)
	sendToWebSocket("用户登录", wsContent, nil, "Info")
}

// handleAttackInfoMessage 处理攻击信息消息
func handleAttackInfoMessage(msg innerbean.AttackInfoMessageInfo) {
	isCanSend := checkCanSend(msg.AttackType)
	if !isCanSend {
		return
	}

	// 1. 加入通知聚合器
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatAttackInfoMessageFromBean(msg)
	gNotifyAgg.Add(notifyEntry{MessageType: messageType, Title: title, Content: content})

	// 2. 发送到 WebSocket（实时推送）
	wsContent := fmt.Sprintf("检测到 %s 攻击，来源IP: %s", msg.AttackType, msg.Ip)
	sendToWebSocket("攻击告警", wsContent, nil, "Info")
}

// handleAccessMessage 处理统一访问认证事件（登录成功 / 安全异常）
//
// 不走通知聚合器：能到这里的事件已经在审计侧过了「事件白名单 + 同事件同IP 5分钟节流」
// 两道闸，量本来就极小；再聚合只会让安全告警晚几十秒到，得不偿失。
func handleAccessMessage(msg innerbean.AccessMessageInfo) {
	// 1. 发送到通知订阅系统。登录成功与异常告警是两个独立的订阅类型，
	//    见 model.MSG_TYPE_ACCESS_LOGIN / MSG_TYPE_ACCESS_ABNORMAL 的注释
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatAccessMessageFromBean(msg)
	waf_service.WafNotifySenderServiceApp.SendNotification(messageType, title, content)

	// 2. 发送到 WebSocket（管理端在线时实时弹出）
	level := "Info"
	if msg.Abnormal {
		level = "Warning"
	}
	who := msg.AccountName
	if who == "" {
		who = "-"
	}
	wsContent := fmt.Sprintf("%s：账号 %s，来源 %s %s", msg.EventName, who, msg.Ip, msg.Location)
	sendToWebSocket("统一访问认证", wsContent, nil, level)
}

// handleWeeklyReportMessage 处理周报消息
func handleWeeklyReportMessage(msg innerbean.WeeklyReportMessageInfo) {
	// 1. 发送到新的通知订阅系统
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatWeeklyReportMessageFromBean(msg)
	waf_service.WafNotifySenderServiceApp.SendNotification(messageType, title, content)

	// 2. 发送到 WebSocket
	wsContent := fmt.Sprintf("周期: %s, 总请求: %d, 拦截: %d", msg.WeekRange, msg.TotalRequests, msg.BlockedRequests)
	sendToWebSocket("WAF周报", wsContent, nil, "Info")
}

// handleSSLExpireMessage 处理SSL证书过期消息
func handleSSLExpireMessage(msg innerbean.SSLExpireMessageInfo) {
	// SSL证书消息总是发送（不受频率限制）
	// 1. 发送到新的通知订阅系统
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatSSLExpireMessageFromBean(msg)
	waf_service.WafNotifySenderServiceApp.SendNotification(messageType, title, content)

	// 2. 发送到 WebSocket
	wsContent := fmt.Sprintf("域名 %s 的SSL证书将在 %d 天后过期", msg.Domain, msg.DaysLeft)
	sendToWebSocket("SSL证书过期提醒", wsContent, nil, "Info")
}

// handleSystemErrorMessage 处理系统错误消息
func handleSystemErrorMessage(msg innerbean.SystemErrorMessageInfo) {
	// 1. 发送到新的通知订阅系统
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatSystemErrorMessageFromBean(msg)
	waf_service.WafNotifySenderServiceApp.SendNotification(messageType, title, content)

	// 2. 发送到 WebSocket
	wsContent := fmt.Sprintf("系统错误: %s - %s", msg.ErrorType, msg.ErrorMsg)
	sendToWebSocket("系统错误", wsContent, nil, "Info")
}

// handleIPBanMessage 处理IP封禁消息
func handleIPBanMessage(msg innerbean.IPBanMessageInfo) {
	isCanSend := checkCanSend(msg.Ip)
	if !isCanSend {
		return
	}

	// 1. 加入通知聚合器
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatIPBanMessageFromBean(msg)
	gNotifyAgg.Add(notifyEntry{MessageType: messageType, Title: title, Content: content})

	// 2. 发送到 WebSocket（实时推送）
	wsContent := fmt.Sprintf("IP %s 已被封禁，原因: %s", msg.Ip, msg.Reason)
	sendToWebSocket("IP封禁通知", wsContent, nil, "Info")
}

// sendToWebSocket 统一的 WebSocket 发送函数
func sendToWebSocket(messageType, messageData string, messageAttach interface{}, cmdType string) {
	for _, ws := range global.GWebSocket.GetAllWebSocket() {
		if ws != nil {
			msgBody, _ := json.Marshal(model.MsgDataPacket{
				MessageId:           uuid.GenUUID(),
				MessageType:         messageType,
				MessageData:         messageData,
				MessageAttach:       messageAttach,
				MessageDateTime:     time.Now().Format("2006-01-02 15:04:05"),
				MessageUnReadStatus: true,
			})
			encryptStr, _ := wafsec.AesEncrypt(msgBody, global.GWAF_COMMUNICATION_KEY)
			msgBytes, err := json.Marshal(model.MsgPacket{
				MsgCode:       "200",
				MsgDataPacket: encryptStr,
				MsgCmdType:    cmdType,
			})
			err = ws.WriteMessage(1, msgBytes)
			if err != nil {
				zlog.Debug("发送websocket错误", err)
				continue
			}
		}
	}
}
