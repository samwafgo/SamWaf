package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model/response"
	"SamWaf/service/waf_service"
	"runtime"
	"time"
)

// TaskStatsPush 定时推送系统统计数据到WebSocket客户端
func TaskStatsPush() {
	innerLogName := "TaskStatsPush"
	// 检查是否启用系统统计数据推送
	if global.GCONFIG_ENABLE_SYSTEM_STATS_PUSH != 1 {
		zlog.Debug(innerLogName, "系统统计数据推送未启用，跳过推送")
		return
	}

	// 先更新实时QPS计算
	global.UpdateRealtimeQPS()

	// 通过系统监控服务获取CPU和内存信息
	systemInfo, err := waf_service.WafSystemMonitorServiceApp.GetSystemMonitorInfo()
	var cpuPercent, memoryPercent float64
	var networkRecv, networkSent, networkRecvRate, networkSentRate uint64
	var systemMonitorPtr *response.WafSystemMonitor

	if err == nil {
		cpuPercent = systemInfo.CPU.UsagePercent
		memoryPercent = systemInfo.Memory.UsagePercent
		networkRecv = systemInfo.Network.BytesRecv
		networkSent = systemInfo.Network.BytesSent
		networkRecvRate = systemInfo.Network.RecvRateBytes
		networkSentRate = systemInfo.Network.SendRateBytes
		// 保存完整的系统监控信息
		systemMonitorPtr = &systemInfo
	} else {
		zlog.Error(innerLogName, "获取系统监控信息失败", "error", err)
		systemMonitorPtr = nil
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
		NetworkRecv:     networkRecv,
		NetworkSent:     networkSent,
		NetworkRecvRate: networkRecvRate,
		NetworkSentRate: networkSentRate,
		SystemMonitor:   systemMonitorPtr, // 添加完整的系统监控信息
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
		"内存使用率", statsData.MemoryPercent,
		"网络接收", statsData.NetworkRecv,
		"网络发送", statsData.NetworkSent,
		"网络接收速率", statsData.NetworkRecvRate,
		"网络发送速率", statsData.NetworkSentRate,
		"系统监控信息", statsData.SystemMonitor)

	global.GQEQUE_MESSAGE_DB.Enqueue(statsData)

}
