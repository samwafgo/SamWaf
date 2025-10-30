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
	"github.com/shirou/gopsutil/v3/net"
)

type WafSystemMonitorService struct {
	lastNetStats     *net.IOCountersStat // 上次网络统计数据
	lastNetStatsTime time.Time           // 上次统计时间
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

	// 获取网络信息
	networkInfo, err := receiver.getNetworkInfo()
	if err != nil {
		return result, fmt.Errorf("获取网络信息失败: %v", err)
	}
	result.Network = networkInfo

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

// getNetworkInfo 获取网络信息
func (receiver *WafSystemMonitorService) getNetworkInfo() (response.WafNetworkInfo, error) {
	var networkInfo response.WafNetworkInfo
	currentTime := time.Now()

	// 获取网络接口统计信息
	netStats, err := net.IOCounters(false) // false表示获取所有接口的汇总信息
	if err != nil {
		return networkInfo, err
	}

	if len(netStats) > 0 {
		// 取第一个（汇总）统计信息
		stat := netStats[0]
		networkInfo.BytesRecv = stat.BytesRecv
		networkInfo.BytesSent = stat.BytesSent

		// 计算实时流量速率
		if receiver.lastNetStats != nil && !receiver.lastNetStatsTime.IsZero() {
			// 计算时间差（秒）
			timeDiff := currentTime.Sub(receiver.lastNetStatsTime).Seconds()
			if timeDiff > 0 {
				// 计算字节差
				recvDiff := stat.BytesRecv - receiver.lastNetStats.BytesRecv
				sentDiff := stat.BytesSent - receiver.lastNetStats.BytesSent

				// 计算每秒速率
				networkInfo.RecvRateBytes = uint64(float64(recvDiff) / timeDiff)
				networkInfo.SendRateBytes = uint64(float64(sentDiff) / timeDiff)

				// 格式化速率字符串
				networkInfo.RecvRate = receiver.formatBytes(networkInfo.RecvRateBytes) + "/s"
				networkInfo.SendRate = receiver.formatBytes(networkInfo.SendRateBytes) + "/s"
			}
		} else {
			// 首次调用，速率为0
			networkInfo.RecvRateBytes = 0
			networkInfo.SendRateBytes = 0
			networkInfo.RecvRate = "0 B/s"
			networkInfo.SendRate = "0 B/s"
		}

		// 更新上次统计数据
		receiver.lastNetStats = &stat
		receiver.lastNetStatsTime = currentTime
	}

	return networkInfo, nil
}
