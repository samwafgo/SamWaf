package wafqueue

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/service/waf_service"
	"SamWaf/utils"
	"SamWaf/wafsec"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

/*
*
处理消息队列信息
*/
func ProcessMessageDequeEngine() {
	// 启动订阅级通知聚合器（按「订阅 × 去重key」分桶，窗口取各订阅自己的配置）
	waf_service.NotifyAggregatorApp.StartFlushLoop(global.GWAF_QUEUE_SHUTDOWN_SIGNAL)

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
					//导出结果
					sendToWebSocket("导出结果", msg.Msg, nil, "DOWNLOAD_LOG")
				case innerbean.UpdateResultMessageInfo:
					//升级结果
					sendToWebSocket("升级结果", msg.Msg, nil, "Info")
				case innerbean.OpResultMessageInfo:
					//操作实时结果
					sendToWebSocket("信息通知", msg.Msg, nil, "Info")
				case innerbean.SystemStatsData:
					//系统统计数据
					sendToWebSocket("系统统计信息", "", msg, "SystemStats")
				}

			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// ========== 通知防雪崩总闸 ==========
//
// 历史包袱说明（issue #822）：
// 这里原本是唯一的频率控制点，用「规则原文」当 key 做 1min→5min→15min 递增冷却。
// 两个问题让它形同虚设：
//   1. 攻击方变换 payload，规则原文就变，每个新串都算"首次出现→立即发送"，冷却被绕过；
//   2. 所有渠道共用一把锁，没法做到"飞书只收严重告警、邮件收全量"。
//
// 现在真正的频率控制下沉到了订阅维度（service/waf_service/waf_notify_throttle.go），
// 这里只保留一道粗粒度总闸，作用仅剩一个：CC 期间事件洪水时保护队列与 goroutine，
// 阈值刻意放宽，正常业务量不会碰到它。

const (
	notifyGateWindow    = time.Second // 限速窗口
	notifyGateMaxPerSec = 50          // 每种消息类型每秒最多放行多少条事件
)

type notifyGateBucket struct {
	windowStart time.Time
	count       int
	dropped     int
}

var (
	notifyGateMu      sync.Mutex
	notifyGateBuckets = make(map[string]*notifyGateBucket)
)

// checkCanSend 防雪崩总闸：按消息类型限速，超出部分直接丢弃（只记 debug 日志，不落库）
func checkCanSend(messageType string) bool {
	now := time.Now()

	notifyGateMu.Lock()
	defer notifyGateMu.Unlock()

	b, ok := notifyGateBuckets[messageType]
	if !ok {
		b = &notifyGateBucket{windowStart: now}
		notifyGateBuckets[messageType] = b
	}
	if now.Sub(b.windowStart) >= notifyGateWindow {
		if b.dropped > 0 {
			zlog.Debug(fmt.Sprintf("通知总闸丢弃事件: 类型=%s 丢弃=%d", messageType, b.dropped))
		}
		b.windowStart = now
		b.count = 0
		b.dropped = 0
	}
	if b.count >= notifyGateMaxPerSec {
		b.dropped++
		return false
	}
	b.count++
	return true
}

// ========== 各类消息处理函数（保持队列+WebSocket方式，集成新的通知系统） ==========

// handleRuleMessage 处理规则触发消息
func handleRuleMessage(msg innerbean.RuleMessageInfo) {
	if !checkCanSend(model.MSG_TYPE_RULE_TRIGGER) {
		return
	}

	// 1. 交给通知订阅系统（逐订阅做频控/过滤/模板，见 waf_notify_throttle.go）
	waf_service.WafNotifySenderServiceApp.SendMessageInfo(msg)

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
	if !checkCanSend(model.MSG_TYPE_OPERATION_NOTICE) {
		return
	}

	// 1. 交给通知订阅系统
	waf_service.WafNotifySenderServiceApp.SendMessageInfo(msg)

	// 2. 保留原有的通知方式
	utils.NotifyHelperApp.SendNoticeInfo(msg)

	// 3. 发送到 WebSocket（实时推送）
	sendToWebSocket(msg.OperaType, msg.OperaCnt, nil, "Info")
}

// handleUserLoginMessage 处理用户登录消息
func handleUserLoginMessage(msg innerbean.UserLoginMessageInfo) {
	// 1. 发送到新的通知订阅系统
	waf_service.WafNotifySenderServiceApp.SendMessageInfo(msg)

	// 2. 发送到 WebSocket
	if msg.Abnormal {
		wsContent := fmt.Sprintf("用户 %s 从 %s 登录，与上次(%s %s)来源不一致", msg.Username, msg.Ip, msg.LastIp, msg.LastLocation)
		sendToWebSocket("登录来源变化", wsContent, nil, "Warning")
		return
	}
	wsContent := fmt.Sprintf("用户 %s 从 %s 登录", msg.Username, msg.Ip)
	sendToWebSocket("用户登录", wsContent, nil, "Info")
}

// handleAttackInfoMessage 处理攻击信息消息
func handleAttackInfoMessage(msg innerbean.AttackInfoMessageInfo) {
	if !checkCanSend(model.MSG_TYPE_ATTACK_INFO) {
		return
	}

	// 1. 交给通知订阅系统
	waf_service.WafNotifySenderServiceApp.SendMessageInfo(msg)

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
	waf_service.WafNotifySenderServiceApp.SendMessageInfo(msg)

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
	waf_service.WafNotifySenderServiceApp.SendMessageInfo(msg)

	// 2. 发送到 WebSocket
	wsContent := fmt.Sprintf("周期: %s, 总请求: %d, 拦截: %d", msg.WeekRange, msg.TotalRequests, msg.BlockedRequests)
	sendToWebSocket("WAF周报", wsContent, nil, "Info")
}

// handleSSLExpireMessage 处理SSL证书过期消息
func handleSSLExpireMessage(msg innerbean.SSLExpireMessageInfo) {
	// SSL证书消息总是发送（不受频率限制）
	// 1. 发送到新的通知订阅系统
	waf_service.WafNotifySenderServiceApp.SendMessageInfo(msg)

	// 2. 发送到 WebSocket
	wsContent := fmt.Sprintf("域名 %s 的SSL证书将在 %d 天后过期", msg.Domain, msg.DaysLeft)
	sendToWebSocket("SSL证书过期提醒", wsContent, nil, "Info")
}

// handleSystemErrorMessage 处理系统错误消息
func handleSystemErrorMessage(msg innerbean.SystemErrorMessageInfo) {
	// 1. 发送到新的通知订阅系统
	waf_service.WafNotifySenderServiceApp.SendMessageInfo(msg)

	// 2. 发送到 WebSocket
	wsContent := fmt.Sprintf("系统错误: %s - %s", msg.ErrorType, msg.ErrorMsg)
	sendToWebSocket("系统错误", wsContent, nil, "Info")
}

// handleIPBanMessage 处理IP封禁消息
func handleIPBanMessage(msg innerbean.IPBanMessageInfo) {
	if !checkCanSend(model.MSG_TYPE_IP_BAN) {
		return
	}

	// 1. 交给通知订阅系统
	waf_service.WafNotifySenderServiceApp.SendMessageInfo(msg)

	// 2. 发送到 WebSocket（实时推送）
	wsContent := fmt.Sprintf("IP %s 已被封禁，原因: %s", msg.Ip, msg.Reason)
	sendToWebSocket("IP封禁通知", wsContent, nil, "Info")

	// 3. 主机防爆破的封禁额外推一条带 HostGuard 命令字的消息，
	//    让「远程防爆破」页面能即时刷新而不必等用户手动点。
	//    单独用一个命令字而不是复用 Info：Info 是通用弹窗通知，
	//    页面刷新逻辑挂上去会让所有通知都触发一次无谓的接口请求。
	if strings.Contains(msg.OperaType, "主机远程登录爆破") {
		sendToWebSocket("主机防爆破封禁", wsContent, msg, "HostGuard")
	}
}

// sendToWebSocket 统一的 WebSocket 发送函数。
// 写入必须走 global.GWebSocket.Broadcast：它按连接加锁串行化并带写超时，
// 直接对裸连接 WriteMessage 会与 ping 回显、定时任务撞成 concurrent write panic。
func sendToWebSocket(messageType, messageData string, messageAttach interface{}, cmdType string) {
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
	if err != nil {
		zlog.Debug("组装websocket报文错误", err)
		return
	}
	global.GWebSocket.Broadcast(websocket.TextMessage, msgBytes)
}
