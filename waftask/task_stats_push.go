package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"runtime"
	"time"
)

// TaskStatsPush 定时推送系统统计数据到WebSocket客户端
func TaskStatsPush() {
	innerLogName := "TaskStatsPush"

	// 先更新实时QPS计算
	global.UpdateRealtimeQPS()

	// 发送WebSocket消息
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var statsData = innerbean.SystemStatsData{
		Timestamp:       time.Now().UnixMilli(),
		QPS:             global.GetRealtimeQPS(),
		LogQPS:          global.GetRealtimeLogQPS(),
		MainQueue:       global.GQEQUE_DB.Size(),
		LogQueue:        global.GQEQUE_LOG_DB.Size(),
		StatsQueue:      global.GQEQUE_STATS_DB.Size(),
		MessageQueue:    global.GQEQUE_MESSAGE_DB.Size(),
		BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "系统统计信息", Server: global.GWAF_CUSTOM_SERVER_NAME},
	}
	zlog.Debug(innerLogName, "系统统计信息",
		"QPS", statsData.QPS,
		"日志QPS", statsData.LogQPS,
		"主队列", statsData.MainQueue,
		"日志队列", statsData.LogQueue,
		"统计队列", statsData.StatsQueue,
		"消息队列", statsData.MessageQueue)

	global.GQEQUE_MESSAGE_DB.Enqueue(statsData)

}
