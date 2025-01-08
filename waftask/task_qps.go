package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/wafenginecore"
	"sync/atomic"
)

// TaskLogQpsClean  清空LOG QPS
func TaskLogQpsClean() {
	innerLogName := "TaskLogQpsClean"
	zlog.Debug(innerLogName, "准备进行TaskLogQpsClean")
	// 清零计数器
	atomic.StoreUint64(&global.GWAF_RUNTIME_QPS, 0)
	atomic.StoreUint64(&global.GWAF_RUNTIME_LOG_PROCESS, 0)
}

// TaskHostQpsClean  清空主机 QPS
func TaskHostQpsClean() {
	innerLogName := "TaskHostQpsClean"
	zlog.Debug(innerLogName, "准备进行TaskHostQpsClean")
	wafenginecore.ResetQPS()
}
