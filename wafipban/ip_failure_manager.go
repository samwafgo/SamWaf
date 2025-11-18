package wafipban

import (
	"SamWaf/cache"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/innerbean"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

func InitIPBanManager() {
	// 注册到innerbean包，供WebLog使用
	innerbean.SetIPFailureCountGetter(func(ip string, minutes int64) int64 {
		return GetIPFailureManager().GetFailureCount(ip, minutes)
	})
}

// IPFailureRecord IP失败记录
type IPFailureRecord struct {
	IP        string
	Count     int64
	FirstTime time.Time
	LastTime  time.Time
}

// IPFailureManager IP失败管理器
type IPFailureManager struct {
	cache     *cache.WafCache
	mu        sync.RWMutex
	statusRe  *regexp.Regexp // 状态码正则表达式
	statusMap map[int]bool   // 状态码快速查找map
}

var (
	ipFailureManagerInstance *IPFailureManager
	ipFailureManagerOnce     sync.Once
)

// GetIPFailureManager 获取IP失败管理器单例
func GetIPFailureManager() *IPFailureManager {
	ipFailureManagerOnce.Do(func() {
		ipFailureManagerInstance = &IPFailureManager{
			cache:     cache.InitWafCache(),
			statusMap: make(map[int]bool),
		}
		ipFailureManagerInstance.initStatusCodes()
	})
	return ipFailureManagerInstance
}

// initStatusCodes 初始化状态码配置
func (m *IPFailureManager) initStatusCodes() {
	m.mu.Lock()
	defer m.mu.Unlock()

	statusCodesStr := global.GCONFIG_IP_FAILURE_STATUS_CODES
	if statusCodesStr == "" {
		statusCodesStr = "401|403|404|444|429|503"
	}

	// 清空现有状态码
	m.statusMap = make(map[int]bool)

	// 尝试解析为数字状态码（用|分隔）
	parts := strings.Split(statusCodesStr, "|")
	hasRegex := false

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 检查是否是正则表达式（包含特殊字符）
		if strings.ContainsAny(part, "^$.*+?[]{}()|\\") {
			hasRegex = true
			break
		}

		// 尝试解析为数字
		if code, err := strconv.Atoi(part); err == nil {
			m.statusMap[code] = true
		}
	}

	// 如果有正则表达式，编译它
	if hasRegex {
		re, err := regexp.Compile("^(" + statusCodesStr + ")$")
		if err != nil {
			zlog.Warn("IP失败状态码正则表达式编译失败", "error", err.Error(), "pattern", statusCodesStr)
		} else {
			m.statusRe = re
		}
	}
}

// ReloadStatusCodes 重新加载状态码配置
func (m *IPFailureManager) ReloadStatusCodes() {
	m.initStatusCodes()
}

// IsFailureStatusCode 检查状态码是否为失败状态码
func (m *IPFailureManager) IsFailureStatusCode(statusCode int) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 先检查快速查找map
	if m.statusMap[statusCode] {
		return true
	}

	// 如果有正则表达式，使用正则匹配
	if m.statusRe != nil {
		statusCodeStr := strconv.Itoa(statusCode)
		return m.statusRe.MatchString(statusCodeStr)
	}

	return false
}

// RecordFailure 记录IP失败
func (m *IPFailureManager) RecordFailure(ip string) {
	if ip == "" || global.GCONFIG_IP_FAILURE_BAN_ENABLED == 0 {
		return
	}

	key := enums.CACHE_IP_FAILURE_PRE + ip
	now := time.Now()

	// 获取现有记录
	var record *IPFailureRecord
	if val := m.cache.Get(key); val != nil {
		if r, ok := val.(*IPFailureRecord); ok {
			record = r
		}
	}

	// 如果记录不存在或已过期，创建新记录
	if record == nil {
		record = &IPFailureRecord{
			IP:        ip,
			Count:     1,
			FirstTime: now,
			LastTime:  now,
		}
	} else {
		// 检查时间窗口
		timeWindow := time.Duration(global.GCONFIG_IP_FAILURE_BAN_TIME_WINDOW) * time.Minute
		if now.Sub(record.FirstTime) > timeWindow {
			// 超出时间窗口，重置计数
			record.Count = 1
			record.FirstTime = now
			record.LastTime = now
		} else {
			// 在时间窗口内，增加计数
			record.Count++
			record.LastTime = now
		}
	}

	// 保存到缓存，TTL设置为时间窗口的2倍
	ttl := time.Duration(global.GCONFIG_IP_FAILURE_BAN_TIME_WINDOW*2) * time.Minute
	m.cache.SetWithTTlRenewTime(key, record, ttl)
}

// GetFailureCount 获取IP在指定时间窗口内的失败次数
// minutes: 时间窗口（分钟）
func (m *IPFailureManager) GetFailureCount(ip string, minutes int64) int64 {
	if ip == "" || global.GCONFIG_IP_FAILURE_BAN_ENABLED == 0 {
		return 0
	}

	key := enums.CACHE_IP_FAILURE_PRE + ip
	val := m.cache.Get(key)
	if val == nil {
		return 0
	}

	record, ok := val.(*IPFailureRecord)
	if !ok {
		return 0
	}

	// 检查时间窗口
	timeWindow := time.Duration(minutes) * time.Minute
	now := time.Now()
	if now.Sub(record.FirstTime) > timeWindow {
		// 超出时间窗口，返回0
		return 0
	}

	return record.Count
}

// IsIPBanned 检查IP是否应该被封禁
func (m *IPFailureManager) IsIPBanned(ip string) bool {
	if ip == "" || global.GCONFIG_IP_FAILURE_BAN_ENABLED == 0 {
		return false
	}

	count := m.GetFailureCount(ip, global.GCONFIG_IP_FAILURE_BAN_TIME_WINDOW)
	return count >= global.GCONFIG_IP_FAILURE_BAN_MAX_COUNT
}

// ClearIPFailure 清除IP的失败记录
func (m *IPFailureManager) ClearIPFailure(ip string) {
	if ip == "" {
		return
	}
	key := enums.CACHE_IP_FAILURE_PRE + ip
	m.cache.Remove(key)
}

// GetFailureInfo 获取IP失败信息（用于调试）
func (m *IPFailureManager) GetFailureInfo(ip string) *IPFailureRecord {
	if ip == "" {
		return nil
	}

	key := enums.CACHE_IP_FAILURE_PRE + ip
	val := m.cache.Get(key)
	if val == nil {
		return nil
	}

	record, ok := val.(*IPFailureRecord)
	if !ok {
		return nil
	}

	return record
}
