package waf_service

import (
	"SamWaf/model/response"
	"fmt"
	"math"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

type WafSystemMonitorService struct {
}

var WafSystemMonitorServiceApp = &WafSystemMonitorService{}

// GetSystemMonitorInfo 获取系统监控信息
func (receiver *WafSystemMonitorService) GetSystemMonitorInfo() (response.WafSystemMonitor, error) {
	var result response.WafSystemMonitor

	// 获取CPU信息
	cpuInfo, err := receiver.getCPUInfo()
	if err != nil {
		return result, fmt.Errorf("获取CPU信息失败: %v", err)
	}
	result.CPU = cpuInfo

	// 获取内存信息
	memInfo, err := receiver.getMemoryInfo()
	if err != nil {
		return result, fmt.Errorf("获取内存信息失败: %v", err)
	}
	result.Memory = memInfo

	// 获取磁盘信息
	diskInfo, err := receiver.getDiskInfo()
	if err != nil {
		return result, fmt.Errorf("获取磁盘信息失败: %v", err)
	}
	result.Disk = diskInfo

	return result, nil
}

// getCPUInfo 获取CPU信息
func (receiver *WafSystemMonitorService) getCPUInfo() (response.WafCPUInfo, error) {
	var cpuInfo response.WafCPUInfo

	// 获取CPU基本信息
	cpuInfos, err := cpu.Info()
	if err != nil {
		return cpuInfo, err
	}

	if len(cpuInfos) > 0 {
		cpuInfo.ModelName = cpuInfos[0].ModelName
		cpuInfo.Cores = cpuInfos[0].Cores
	}

	// 获取CPU使用率
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return cpuInfo, err
	}
	if len(cpuPercent) > 0 {
		cpuInfo.UsagePercent = math.Round(cpuPercent[0])
	}

	// 获取CPU核心数
	physicalCnt, _ := cpu.Counts(false)
	logicalCnt, _ := cpu.Counts(true)
	cpuInfo.PhysicalCnt = physicalCnt
	cpuInfo.LogicalCnt = logicalCnt

	return cpuInfo, nil
}

// getMemoryInfo 获取内存信息
func (receiver *WafSystemMonitorService) getMemoryInfo() (response.WafMemoryInfo, error) {
	var memInfo response.WafMemoryInfo

	// 获取系统内存信息
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return memInfo, err
	}

	memInfo.Total = receiver.formatBytes(vmStat.Total)
	memInfo.Available = receiver.formatBytes(vmStat.Available)
	memInfo.Used = receiver.formatBytes(vmStat.Used)
	memInfo.UsagePercent = math.Round(vmStat.UsedPercent)

	// 获取Go程序内存使用情况
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memInfo.JVMUsed = receiver.formatBytes(m.Alloc)
	if vmStat.Total > 0 {
		jvmPercent := float64(m.Alloc) / float64(vmStat.Total) * 100
		memInfo.JVMPercent = receiver.roundToTwoDecimal(jvmPercent)
	}

	return memInfo, nil
}

// getDiskInfo 获取磁盘信息
func (receiver *WafSystemMonitorService) getDiskInfo() ([]response.WafDiskInfo, error) {
	var diskInfos []response.WafDiskInfo

	// 获取磁盘分区信息
	partitions, err := disk.Partitions(false)
	if err != nil {
		return diskInfos, err
	}

	for _, partition := range partitions {
		// 获取磁盘使用情况
		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			continue // 跳过无法访问的分区
		}

		diskInfo := response.WafDiskInfo{
			FileSystem:   partition.Device,
			MountPoint:   partition.Mountpoint,
			Total:        receiver.formatBytes(usage.Total),
			Available:    receiver.formatBytes(usage.Free),
			Used:         receiver.formatBytes(usage.Used),
			UsagePercent: receiver.roundToTwoDecimal(usage.UsedPercent),
		}

		diskInfos = append(diskInfos, diskInfo)
	}

	return diskInfos, nil
}

// roundToTwoDecimal 将浮点数四舍五入到两位小数
func (receiver *WafSystemMonitorService) roundToTwoDecimal(value float64) float64 {
	return math.Round(value*100) / 100
}

// formatBytes 格式化字节数为可读格式
func (receiver *WafSystemMonitorService) formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
