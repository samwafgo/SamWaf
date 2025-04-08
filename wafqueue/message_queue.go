package wafqueue

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/wafsec"
	"encoding/json"
	"time"
)

/*
*
处理消息队列信息
*/
func ProcessMessageDequeEngine() {
	for {
		for !global.GQEQUE_MESSAGE_DB.Empty() {
			popFront, ok := global.GQEQUE_MESSAGE_DB.Dequeue()
			if !ok {
				zlog.Error("来得信息未空")
				continue
			}
			messageinfo := popFront.(interface{})
			isCanSend := false
			switch messageinfo.(type) {
			case innerbean.RuleMessageInfo:
				rulemessage := messageinfo.(innerbean.RuleMessageInfo)

				isCanSend = checkCanSend(rulemessage.RuleInfo)
				if isCanSend {
					if global.GWAF_NOTICE_ENABLE == false {
						zlog.Info("通知关闭状态")
					} else {
						utils.NotifyHelperApp.SendRuleInfo(rulemessage)
					}
					if rulemessage.BaseMessageInfo.OperaType == "命中保护规则" {
						//发送websocket
						for _, ws := range global.GWebSocket.GetAllWebSocket() {

							if ws != nil {
								msgBody, _ := json.Marshal(model.MsgDataPacket{
									MessageId:           uuid.GenUUID(),
									MessageType:         "命中保护规则",
									MessageData:         rulemessage.RuleInfo + rulemessage.Ip,
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
									continue
								}
							}
						}
					}
				}

				break
			case innerbean.OperatorMessageInfo:
				operatorMessage := messageinfo.(innerbean.OperatorMessageInfo)
				isCanSend = checkCanSend(operatorMessage.OperaType)
				if !isCanSend {
					continue
				}
				utils.NotifyHelperApp.SendNoticeInfo(operatorMessage)
				//发送websocket
				for _, ws := range global.GWebSocket.GetAllWebSocket() {

					if ws != nil {
						msgBody, _ := json.Marshal(model.MsgDataPacket{
							MessageId:           uuid.GenUUID(),
							MessageType:         operatorMessage.OperaType,
							MessageData:         operatorMessage.OperaCnt,
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
							continue
						}
					}
				}
				break
			case innerbean.ExportResultMessageInfo:
				exportResult := messageinfo.(innerbean.ExportResultMessageInfo)
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
				break
			case innerbean.UpdateResultMessageInfo:
				//升级结果
				updatemessage := messageinfo.(innerbean.UpdateResultMessageInfo)
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
				break
			case innerbean.OpResultMessageInfo:
				//操作实时结果
				updatemessage := messageinfo.(innerbean.OpResultMessageInfo)
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
				break
			}

		}
		time.Sleep(100 * time.Millisecond)
	}
}

// checkCanSend 抑止发送频率
func checkCanSend(key string) bool {
	isCanSend := false
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
