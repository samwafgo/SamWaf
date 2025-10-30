package waftask

import (
	"SamWaf/common/zlog"
	"SamWaf/wafdb"
	"time"
)

// TaskDatabaseMonitor 数据库监控任务 - 每天凌晨1点执行数据库性能指标打印
func TaskDatabaseMonitor() {
	innerLogName := "TaskDatabaseMonitor"

	zlog.Info(innerLogName, "开始执行数据库监控任务", "执行时间", time.Now().Format("2006-01-02 15:04:05"))

	// 调用数据库性能指标打印函数
	wafdb.PrintDatabaseMetrics()

	zlog.Info(innerLogName, "数据库监控任务执行完成", "完成时间", time.Now().Format("2006-01-02 15:04:05"))
}
