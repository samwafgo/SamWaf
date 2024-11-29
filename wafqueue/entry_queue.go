package wafqueue

import (
	"SamWaf/common/queue"
	"SamWaf/global"
)

/*
*
初始化队列
*/
func InitDequeEngine() {
	global.GQEQUE_DB = queue.NewQueue()
	global.GQEQUE_UPDATE_DB = queue.NewQueue()
	global.GQEQUE_LOG_DB = queue.NewQueue()
	global.GQEQUE_STATS_DB = queue.NewQueue()
	global.GQEQUE_STATS_UPDATE_DB = queue.NewQueue()
	global.GQEQUE_MESSAGE_DB = queue.NewQueue()
}
