package waftunnelengine

import (
	"SamWaf/common/zlog"
	"SamWaf/model"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TimeRange 时间范围结构
type TimeRange struct {
	Start time.Time // 开始时间
	End   time.Time // 结束时间
}

// ParseTimeRanges 解析时间范围字符串
// 格式: "08:00-10:00;11:00-12:00"
// 返回: TimeRange 切片和错误信息
func ParseTimeRanges(timeRangesStr string) ([]TimeRange, error) {
	// 如果为空，返回空切片（表示无限制）
	if strings.TrimSpace(timeRangesStr) == "" {
		return []TimeRange{}, nil
	}

	var ranges []TimeRange
	// 按分号分割多个时间段
	parts := strings.Split(timeRangesStr, ";")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 按减号分割开始和结束时间
		timeParts := strings.Split(part, "-")
		if len(timeParts) != 2 {
			return nil, fmt.Errorf("无效的时间范围格式: %s, 应为 HH:MM-HH:MM", part)
		}

		startStr := strings.TrimSpace(timeParts[0])
		endStr := strings.TrimSpace(timeParts[1])

		// 解析开始时间
		startTime, err := parseTime(startStr)
		if err != nil {
			return nil, fmt.Errorf("解析开始时间失败 %s: %v", startStr, err)
		}

		// 解析结束时间
		endTime, err := parseTime(endStr)
		if err != nil {
			return nil, fmt.Errorf("解析结束时间失败 %s: %v", endStr, err)
		}

		ranges = append(ranges, TimeRange{
			Start: startTime,
			End:   endTime,
		})
	}

	return ranges, nil
}

// parseTime 解析时间字符串 HH:MM
func parseTime(timeStr string) (time.Time, error) {
	parts := strings.Split(timeStr, ":")
	if len(parts) != 2 {
		return time.Time{}, fmt.Errorf("无效的时间格式: %s, 应为 HH:MM", timeStr)
	}

	hour, err := strconv.Atoi(parts[0])
	if err != nil || hour < 0 || hour > 23 {
		return time.Time{}, fmt.Errorf("无效的小时: %s", parts[0])
	}

	minute, err := strconv.Atoi(parts[1])
	if err != nil || minute < 0 || minute > 59 {
		return time.Time{}, fmt.Errorf("无效的分钟: %s", parts[1])
	}

	// 使用今天的日期，只关注时间部分
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location()), nil
}

// IsTimeAllowed 检查当前时间是否在允许的时间范围内
func IsTimeAllowed(timeRanges []TimeRange, currentTime time.Time) bool {
	// 如果没有时间限制，总是允许
	if len(timeRanges) == 0 {
		return true
	}

	// 只比较时分，忽略日期
	currentHour := currentTime.Hour()
	currentMinute := currentTime.Minute()
	currentTimeOfDay := currentHour*60 + currentMinute // 转换为分钟数

	for _, tr := range timeRanges {
		startTimeOfDay := tr.Start.Hour()*60 + tr.Start.Minute()
		endTimeOfDay := tr.End.Hour()*60 + tr.End.Minute()

		// 处理跨午夜的情况（例如 23:00-01:00）
		if endTimeOfDay < startTimeOfDay {
			// 跨午夜：当前时间在开始时间之后或结束时间之前
			if currentTimeOfDay >= startTimeOfDay || currentTimeOfDay <= endTimeOfDay {
				return true
			}
		} else {
			// 正常情况：当前时间在开始和结束时间之间
			if currentTimeOfDay >= startTimeOfDay && currentTimeOfDay <= endTimeOfDay {
				return true
			}
		}
	}

	return false
}

// CheckTimeAccess 检查隧道的时间访问权限
func CheckTimeAccess(protocol string, clientIP string, clientPort string, serverPort string, tunnel model.Tunnel) bool {
	// 解析时间范围
	timeRanges, err := ParseTimeRanges(tunnel.AllowedTimeRanges)
	if err != nil {
		zlog.Error(fmt.Sprintf("解析时间范围失败 [协议:%s 客户端IP:%s 客户端端口:%s 服务端口:%s 错误:%s]",
			protocol, clientIP, clientPort, serverPort, err.Error()))
		// 解析失败时，为了安全起见，拒绝访问
		return false
	}

	// 检查当前时间是否允许访问
	currentTime := time.Now()
	allowed := IsTimeAllowed(timeRanges, currentTime)

	if !allowed {
		zlog.Warn(fmt.Sprintf("%s连接被时间限制拒绝 [客户端IP:%s 客户端端口:%s 服务端口:%s 当前时间:%s 允许时间段:%s]",
			protocol, clientIP, clientPort, serverPort, currentTime.Format("15:04"), tunnel.AllowedTimeRanges))
	}

	return allowed
}
