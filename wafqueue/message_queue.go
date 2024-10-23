package wafqueue

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/wafsec"
	"encoding/json"
	uuid "github.com/satori/go.uuid"
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
				couter := 1
				if global.GCACHE_WAFCACHE.IsKeyExist(rulemessage.RuleInfo) {
					hitCounter, isok := global.GCACHE_WAFCACHE.GetInt(rulemessage.RuleInfo)
					if isok == nil {
						if hitCounter == 3 || hitCounter == 30 {
							isCanSend = true
						}
						couter = couter + 1
					}
				} else {
					isCanSend = true
				}
				global.GCACHE_WAFCACHE.SetWithTTl(rulemessage.RuleInfo, 1, 30*time.Minute)
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
									MessageId:           uuid.NewV4().String(),
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
				utils.NotifyHelperApp.SendNoticeInfo(operatorMessage)
				break
			case innerbean.ExportResultMessageInfo:
				exportResult := messageinfo.(innerbean.ExportResultMessageInfo)
				//发送websocket
				for _, ws := range global.GWebSocket.GetAllWebSocket() {
					if ws != nil {
						//信息包体进行单独处理
						msgBody, _ := json.Marshal(model.MsgDataPacket{
							MessageId:           uuid.NewV4().String(),
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
							MessageId:           uuid.NewV4().String(),
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
							MessageId:           uuid.NewV4().String(),
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
