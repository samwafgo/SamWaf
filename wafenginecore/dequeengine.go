package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/utils"
	"encoding/json"
	"github.com/edwingeng/deque"
	uuid "github.com/satori/go.uuid"
	"time"
)

/*
*
初始化队列
*/
func InitDequeEngine() {
	global.GQEQUE_DB = deque.NewDeque()
	global.GQEQUE_LOG_DB = deque.NewDeque()
	global.GQEQUE_MESSAGE_DB = deque.NewDeque()
}

/*
*
处理队列信息
*/
func ProcessDequeEngine() {
	for {
		for !global.GQEQUE_DB.Empty() {
			weblogbean := global.GQEQUE_DB.PopFront()
			global.GWAF_LOCAL_DB.Create(weblogbean)
			//zlog.Info("DB", weblogbean)
		}

		for !global.GQEQUE_LOG_DB.Empty() {
			weblogbean := global.GQEQUE_LOG_DB.PopFront()
			global.GWAF_LOCAL_LOG_DB.Create(weblogbean)
			//zlog.Info("LOGDB", weblogbean)
		}

		for !global.GQEQUE_MESSAGE_DB.Empty() {
			messageinfo := global.GQEQUE_MESSAGE_DB.PopFront().(innerbean.MessageInfo)
			utils.NotifyHelperApp.SendInfo(messageinfo.Title, messageinfo.Content, messageinfo.Remarks)
			if messageinfo.Title == "命中保护规则" {
				//发送websocket
				for _, ws := range global.GWebSocket {
					if ws != nil {
						//写入ws数据
						msgBytes, err := json.Marshal(model.MsgPacket{
							MessageId:           uuid.NewV4().String(),
							MessageType:         "命中保护规则",
							MessageData:         messageinfo.Content,
							MessageAttach:       nil,
							MessageDateTime:     time.Now().Format("2006-01-02 15:04:05"),
							MessageUnReadStatus: true,
						})
						err = ws.WriteMessage(1, msgBytes)
						if err != nil {
							continue
						}
					}
				}
			}
			//zlog.Info("MESSAGE", messageinfo)
		}
		time.Sleep(1)
	}
}
