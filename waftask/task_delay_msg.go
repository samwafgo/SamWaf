package waftask

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/service/waf_service"
	"SamWaf/wafsec"
	"encoding/json"
	"time"

	"github.com/gorilla/websocket"
)

// TaskDelayInfo 定时发送延迟信息
func TaskDelayInfo() {
	zlog.Debug("TaskDelayInfo")
	models, count, err := waf_service.WafDelayMsgServiceApp.GetAllList()
	if err == nil {
		if count > 0 {
			for i := 0; i < len(models); i++ {
				msg := models[i]

				cmdType := "Info"
				if msg.DelayType == "升级结果" {
					cmdType = "RELOAD_PAGE"
				}
				msgBody, _ := json.Marshal(model.MsgDataPacket{
					MessageId:           uuid.GenUUID(),
					MessageType:         msg.DelayType,
					MessageData:         msg.DelayContent,
					MessageAttach:       nil,
					MessageDateTime:     time.Now().Format("2006-01-02 15:04:05"),
					MessageUnReadStatus: true,
				})
				encryptStr, _ := wafsec.AesEncrypt(msgBody, global.GWAF_COMMUNICATION_KEY)
				msgBytes, err := json.Marshal(
					model.MsgPacket{
						MsgCode:       "200",
						MsgDataPacket: encryptStr,
						MsgCmdType:    cmdType,
					})
				if err != nil {
					zlog.Debug("组装延迟消息报文错误", err)
					continue
				}
				//发送websocket：走会话管理器统一出口，内部按连接加锁 + 写超时
				sendSuccess := global.GWebSocket.Broadcast(websocket.TextMessage, msgBytes)

				if sendSuccess > 0 {
					waf_service.WafDelayMsgServiceApp.DelApi(msg.Id)
				}

			}
		}
	}
}
