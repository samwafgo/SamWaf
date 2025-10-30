package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/utils"
	"SamWaf/wafenginecore"
)

// TaskLogQpsClean  清空LOG QPS
func TaskLogQpsClean() {
	innerLogName := "TaskLogQpsClean"
	if utils.CheckDebugEnvInfo() {
		zlog.Debug(innerLogName, "准备进行TaskLogQpsClean")
	}

	// 更新实时QPS计算 (基于差分计算)
	global.UpdateRealtimeQPS()
}

// TaskHostQpsClean  清空主机 QPS
func TaskHostQpsClean() {
	innerLogName := "TaskHostQpsClean"
	if utils.CheckDebugEnvInfo() {
		zlog.Debug(innerLogName, "准备进行TaskHostQpsClean")
	}
	wafenginecore.ResetQPS()
}
