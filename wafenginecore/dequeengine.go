package wafenginecore

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/utils"
	"SamWaf/utils/zlog"
	"github.com/edwingeng/deque"
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
			zlog.Info("DB", weblogbean)
		}

		for !global.GQEQUE_LOG_DB.Empty() {
			weblogbean := global.GQEQUE_LOG_DB.PopFront()
			global.GWAF_LOCAL_LOG_DB.Create(weblogbean)
			zlog.Info("LOGDB", weblogbean)
		}

		for !global.GQEQUE_MESSAGE_DB.Empty() {
			messageinfo := global.GQEQUE_MESSAGE_DB.PopFront().(innerbean.MessageInfo)
			utils.NotifyHelperApp.SendInfo(messageinfo.Title, messageinfo.Content, messageinfo.Remarks)
			zlog.Info("MESSAGE", messageinfo)
		}
		time.Sleep(1)
	}
}
