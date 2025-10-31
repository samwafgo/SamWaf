package wafdb

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"testing"
	"time"
)

// TestDatabaseMonitoring 测试数据库监控功能
func TestDatabaseMonitoring(t *testing.T) {
	t.Parallel()

	//初始化日志
	zlog.InitZLog(global.GWAF_LOG_DEBUG_ENABLE, "console")
	// 初始化数据库
	_, err := InitCoreDb("")
	if err != nil {
		t.Fatalf("初始化主数据库失败: %v", err)
	}

	_, err = InitLogDb("")
	if err != nil {
		t.Fatalf("初始化日志数据库失败: %v", err)
	}

	_, err = InitStatsDb("")
	if err != nil {
		t.Fatalf("初始化统计数据库失败: %v", err)
	}

	// 打印数据库性能指标
	zlog.Info("=== 开始数据库性能监控测试 ===")
	PrintDatabaseMetrics()

	// 获取JSON格式的指标
	jsonMetrics, err := GetDatabaseMetricsJSON()
	if err != nil {
		t.Errorf("获取JSON格式指标失败: %v", err)
	} else {
		zlog.Info("JSON格式指标:")
		zlog.Info(jsonMetrics)
	}
}

// TestDatabaseMonitoringLoop 测试定时监控功能
func TestDatabaseMonitoringLoop(t *testing.T) {
	// 初始化数据库
	InitCoreDb("")
	InitLogDb("")
	InitStatsDb("")

	// 启动定时监控（每1分钟监控一次，仅用于测试）
	StartDatabaseMonitoring(1)

	// 等待几秒钟观察监控输出
	time.Sleep(5 * time.Second)

	zlog.Info("定时监控已启动，请查看日志输出")
}

// BenchmarkDatabaseMetrics 性能基准测试
func BenchmarkDatabaseMetrics(b *testing.B) {
	// 初始化数据库
	InitCoreDb("")
	InitLogDb("")
	InitStatsDb("")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := MonitorAllDatabases()
		if err != nil {
			b.Errorf("监控数据库失败: %v", err)
		}
	}
}
