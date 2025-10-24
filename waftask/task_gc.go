package waftask

import (
	"SamWaf/common/zlog"
	"runtime"
)

func TaskGC() {
	innerLogName := "TaskGC"

	// 获取GC前的内存统计
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	zlog.Info(innerLogName, "准备进行GC回收",
		"GC前内存使用", m1.Alloc/1024/1024, "MB",
		"GC前堆内存", m1.HeapAlloc/1024/1024, "MB",
		"GC前系统内存", m1.Sys/1024/1024, "MB",
		"GC次数", m1.NumGC)

	// 执行GC
	runtime.GC()

	// 获取GC后的内存统计
	runtime.ReadMemStats(&m2)

	// 计算内存释放量
	memFreed := int64(m1.Alloc) - int64(m2.Alloc)
	heapFreed := int64(m1.HeapAlloc) - int64(m2.HeapAlloc)

	zlog.Info(innerLogName, "GC回收完成",
		"GC后内存使用", m2.Alloc/1024/1024, "MB",
		"GC后堆内存", m2.HeapAlloc/1024/1024, "MB",
		"GC后系统内存", m2.Sys/1024/1024, "MB",
		"GC次数", m2.NumGC,
		"释放内存", memFreed/1024/1024, "MB",
		"释放堆内存", heapFreed/1024/1024, "MB",
		"GC耗时", m2.PauseTotalNs-m1.PauseTotalNs, "ns")
}
