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

// checkCanSend 抑止发送频率
func checkCanSend(key string) bool {
	isCanSend := false
	// SSL证书相关的消息（包括申请和续期）都直接发送，不受频率限制
	if strings.HasPrefix(key, "SSL证书") {
		isCanSend = true
		return isCanSend
	}
	noticeKeyInfo := enums.CACHE_NOTICE_PRE + key
	// 检查规则信息是否存在
	if global.GCACHE_WAFCACHE.IsKeyExist(noticeKeyInfo) {
		// 获取当前计数
		hitCounter, isOk := global.GCACHE_WAFCACHE.GetInt(noticeKeyInfo)
		if isOk == nil {
			zlog.Debug("current hitCounter", hitCounter)
			// 检查是否到达指定触发次数
			if hitCounter == 1 || hitCounter == 3 || hitCounter == 30 {
				isCanSend = true // 可以发送
				// 增加计数
				hitCounter++
				global.GCACHE_WAFCACHE.SetWithTTl(noticeKeyInfo, hitCounter, global.GNOTIFY_SEND_MAX_LIMIT_MINTUTES)
			} else {
				// 增加计数
				hitCounter++
				global.GCACHE_WAFCACHE.SetWithTTl(noticeKeyInfo, hitCounter, global.GNOTIFY_SEND_MAX_LIMIT_MINTUTES)
				// 如果达到次数，不再继续处理
				isCanSend = false
			}
		}
	} else {
		// 如果规则信息不存在，或未达到触发次数
		global.GCACHE_WAFCACHE.SetWithTTl(noticeKeyInfo, 1, global.GNOTIFY_SEND_MAX_LIMIT_MINTUTES) // 初始化计数
	}
	return isCanSend
}

// ========== 各类消息处理函数（保持队列+WebSocket方式，集成新的通知系统） ==========

// handleRuleMessage 处理规则触发消息
func handleRuleMessage(msg innerbean.RuleMessageInfo) {
	isCanSend := checkCanSend(msg.RuleInfo)
	if !isCanSend {
		return
	}

	// 1. 发送到新的通知订阅系统（使用格式化后的消息）
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatRuleMessage(msg)
	waf_service.WafNotifySenderServiceApp.SendNotification(messageType, title, content)

	// 2. 保留原有的通知方式（兼容旧系统）
	if global.GWAF_NOTICE_ENABLE {
		utils.NotifyHelperApp.SendRuleInfo(msg)
	} else {
		zlog.Debug("通知关闭状态")
	}

	// 3. 发送到 WebSocket（保持原有功能）
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

	// 1. 发送到新的通知订阅系统
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatOperatorMessage(msg)
	waf_service.WafNotifySenderServiceApp.SendNotification(messageType, title, content)

	// 2. 保留原有的通知方式
	utils.NotifyHelperApp.SendNoticeInfo(msg)

	// 3. 发送到 WebSocket
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

	// 1. 发送到新的通知订阅系统
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatAttackInfoMessageFromBean(msg)
	waf_service.WafNotifySenderServiceApp.SendNotification(messageType, title, content)

	// 2. 发送到 WebSocket
	wsContent := fmt.Sprintf("检测到 %s 攻击，来源IP: %s", msg.AttackType, msg.Ip)
	sendToWebSocket("攻击告警", wsContent, nil, "Info")
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

	// 1. 发送到新的通知订阅系统
	messageType, title, content := waf_service.WafNotifySenderServiceApp.FormatIPBanMessageFromBean(msg)
	waf_service.WafNotifySenderServiceApp.SendNotification(messageType, title, content)

	// 2. 发送到 WebSocket
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
