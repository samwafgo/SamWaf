package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"math"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// TaskStatsPush 定时推送系统统计数据到WebSocket客户端
func TaskStatsPush() {
	innerLogName := "TaskStatsPush"

	// 先更新实时QPS计算
	global.UpdateRealtimeQPS()

	// 获取CPU使用率
	var cpuPercent float64
	cpuPercentSlice, err := cpu.Percent(100*time.Millisecond, false)
	if err == nil && len(cpuPercentSlice) > 0 {
		cpuPercent = math.Round(cpuPercentSlice[0])
	}

	// 获取内存使用率
	var memoryPercent float64
	vmStat, err := mem.VirtualMemory()
	if err == nil {
		memoryPercent = math.Round(vmStat.UsedPercent)
	}

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
		CPUPercent:      cpuPercent,
		MemoryPercent:   memoryPercent,
		BaseMessageInfo: innerbean.BaseMessageInfo{OperaType: "系统统计信息", Server: global.GWAF_CUSTOM_SERVER_NAME},
	}
	zlog.Debug(innerLogName, "系统统计信息",
		"QPS", statsData.QPS,
		"日志QPS", statsData.LogQPS,
		"主队列", statsData.MainQueue,
		"日志队列", statsData.LogQueue,
		"统计队列", statsData.StatsQueue,
		"消息队列", statsData.MessageQueue,
		"CPU使用率", statsData.CPUPercent,
		"内存使用率", statsData.MemoryPercent)

	global.GQEQUE_MESSAGE_DB.Enqueue(statsData)

}
