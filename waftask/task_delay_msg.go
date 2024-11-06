package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/service/waf_service"
	"SamWaf/wafsec"
	"encoding/json"
	uuid "github.com/satori/go.uuid"
	"time"
)

// TaskDelayInfo 定时发送延迟信息
func TaskDelayInfo() {
	zlog.Debug("TaskDelayInfo")
	models, count, err := waf_service.WafDelayMsgServiceApp.GetAllList()
	if err == nil {
		if count > 0 {
			for i := 0; i < len(models); i++ {
				msg := models[i]
				sendSuccess := 0
				//发送websocket
				for _, ws := range global.GWebSocket.GetAllWebSocket() {
					if ws != nil {

						cmdType := "Info"
						if msg.DelayType == "升级结果" {
							cmdType = "RELOAD_PAGE"
						}
						msgBody, _ := json.Marshal(model.MsgDataPacket{
							MessageId:           uuid.NewV4().String(),
							MessageType:         msg.DelayType,
							MessageData:         msg.DelayContent,
							MessageAttach:       nil,
							MessageDateTime:     time.Now().Format("2006-01-02 15:04:05"),
							MessageUnReadStatus: true,
						})
						encryptStr, _ := wafsec.AesEncrypt(msgBody, global.GWAF_COMMUNICATION_KEY)
						//写入ws数据
						msgBytes, err := json.Marshal(
							model.MsgPacket{
								MsgCode:       "200",
								MsgDataPacket: encryptStr,
								MsgCmdType:    cmdType,
							})
						err = ws.WriteMessage(1, msgBytes)
						if err != nil {
							continue
						} else {
							sendSuccess = sendSuccess + 1
						}
					}
				}

				if sendSuccess > 0 {
					waf_service.WafDelayMsgServiceApp.DelApi(msg.Id)
				}

			}
		}
	}
}
