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

func InitIPBanManager(wafCache cache.CacheStore) {
	// 初始化IP失败管理器单例，使用传入的cache
	ipFailureManagerOnce.Do(func() {
		ipFailureManagerInstance = &IPFailureManager{
			cache:     wafCache,
			statusMap: make(map[int]bool),
		}
		ipFailureManagerInstance.initStatusCodes()
	})

	// 注册到innerbean包，供WebLog使用
	innerbean.SetIPFailureCountGetter(func(ip string, minutes int64) int64 {
		return GetIPFailureManager().GetFailureCount(ip, minutes)
	})
	// 注册IP失败封禁阈值记录函数
	innerbean.SetIPFailureThresholdRecorder(func(ip string, minutes int64, count int64) {
		GetIPFailureManager().RecordFailureThreshold(ip, minutes, count)
	})
	// 生产规则链使用带错误返回的回调，不能把共享后端故障解释成零失败次数。
	innerbean.SetIPFailureCountGetterE(func(ip string, minutes int64) (int64, error) {
		return GetIPFailureManager().GetFailureCountE(ip, minutes)
	})
	innerbean.SetIPFailureThresholdRecorderE(func(ip string, minutes, count int64) error {
		return GetIPFailureManager().RecordFailureThreshold(ip, minutes, count)
	})
	// 注册SSL证书验证路径获取函数
	innerbean.SetSSLChallengePathGetter(func() string {
		return global.GSSL_HTTP_CHANGLE_PATH
	})
}

// IPFailureRecord IP失败记录
type IPFailureRecord struct {
	IP             string
	Events         []time.Time
	Count          int64
	FirstTime      time.Time
	LastTime       time.Time
	TriggerMinutes int64 // 触发封禁的时间窗口（分钟）
	TriggerCount   int64 // 触发封禁的失败次数阈值
}

// IPFailureManager IP失败管理器
type IPFailureManager struct {
	cache     cache.CacheStore
	mu        sync.RWMutex
	statusRe  *regexp.Regexp // 状态码正则表达式
	statusMap map[int]bool   // 状态码快速查找map
}

var (
	ipFailureManagerInstance *IPFailureManager
	ipFailureManagerOnce     sync.Once
)

// GetIPFailureManager 获取IP失败管理器单例
// 注意：需要先调用 InitIPBanManager 进行初始化
func GetIPFailureManager() *IPFailureManager {
	if ipFailureManagerInstance == nil {
		zlog.Error("IPFailureManager 未初始化，请先调用 InitIPBanManager")
	}
	return ipFailureManagerInstance
}

// load 读取 IP 的失败记录（共享快照，只读）
func (m *IPFailureManager) load(ip string) *IPFailureRecord {
	return loadRecord[IPFailureRecord](m.cache, enums.CACHE_IP_FAILURE_PRE+ip)
}

// cloneIPFailureRecord 克隆记录及其事件切片，供写路径改副本用
func cloneIPFailureRecord(r *IPFailureRecord) *IPFailureRecord {
	if r == nil {
		return nil
	}
	c := *r
	c.Events = append([]time.Time(nil), r.Events...)
	return &c
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

// RecordFailure 记录一次失败；数据库事务串行化同 IP 的跨 Worker 更新。
func (m *IPFailureManager) RecordFailure(webLog *innerbean.WebLog) error {
	if webLog == nil || webLog.SkipFailureCount || global.GCONFIG_IP_FAILURE_BAN_ENABLED == 0 {
		return nil
	}
	ip := webLog.SecurityIP
	if ip == "" {
		ip = webLog.SRC_IP
	}
	if ip == "" {
		return nil
	}
	if webLog.IsBot == 1 && webLog.RISK_LEVEL == 0 {
		return nil
	}
	if global.GSSL_HTTP_CHANGLE_PATH != "" && strings.HasPrefix(webLog.URL, global.GSSL_HTTP_CHANGLE_PATH) {
		return nil
	}
	if _, shared := m.cache.(cache.JSONUpdater); !shared {
		m.mu.Lock()
		defer m.mu.Unlock()
	}
	ttl := time.Duration(global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME) * time.Minute
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return updateRecord[IPFailureRecord](m.cache, enums.CACHE_IP_FAILURE_PRE+ip, ttl, func(previous *IPFailureRecord) *IPFailureRecord {
		now := time.Now()
		record := cloneIPFailureRecord(previous)
		if record == nil {
			record = &IPFailureRecord{IP: ip, FirstTime: now}
		}
		record.Events = append(record.Events, now)
		start := now.Add(-ttl)
		valid := make([]time.Time, 0, len(record.Events))
		for _, at := range record.Events {
			if at.After(start) {
				valid = append(valid, at)
			}
		}
		record.Events = valid
		record.Count = int64(len(valid))
		if len(valid) > 0 {
			record.FirstTime = valid[0]
		}
		record.LastTime = now
		return record
	})
}

// GetFailureCount 保留旧统计接口；请求规则使用 GetFailureCountE，显式传播故障。
func (m *IPFailureManager) GetFailureCount(ip string, minutes int64) int64 {
	count, _ := m.GetFailureCountE(ip, minutes)
	return count
}

// GetFailureCountE 在指定窗口读取真实计数，数据库故障与零次失败分开返回。
func (m *IPFailureManager) GetFailureCountE(ip string, minutes int64) (int64, error) {
	if ip == "" || global.GCONFIG_IP_FAILURE_BAN_ENABLED == 0 {
		return 0, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	record, err := readRecordE[IPFailureRecord](m.cache, enums.CACHE_IP_FAILURE_PRE+ip)
	if err != nil || record == nil {
		return 0, err
	}
	start := time.Now().Add(-time.Duration(minutes) * time.Minute)
	var count int64
	for _, at := range record.Events {
		if at.After(start) {
			count++
		}
	}
	return count, nil
}

// ClearIPFailure 清除IP的失败记录
func (m *IPFailureManager) ClearIPFailure(ip string) {
	if ip == "" {
		return
	}
	key := enums.CACHE_IP_FAILURE_PRE + ip
	m.cache.Remove(key)
}

// GetFailureInfo 获取IP失败信息（返回只读快照，调用方不得修改）
func (m *IPFailureManager) GetFailureInfo(ip string) *IPFailureRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.load(ip)
}

// RecordFailureThreshold 与失败事件共用同键事务，阈值戳不会被其他 Worker 的事件写入覆盖。
func (m *IPFailureManager) RecordFailureThreshold(ip string, minutes, count int64) error {
	if ip == "" || global.GCONFIG_IP_FAILURE_BAN_ENABLED == 0 {
		return nil
	}
	if _, shared := m.cache.(cache.JSONUpdater); !shared {
		m.mu.Lock()
		defer m.mu.Unlock()
	}
	ttl := time.Duration(global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME) * time.Minute
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return updateRecord[IPFailureRecord](m.cache, enums.CACHE_IP_FAILURE_PRE+ip, ttl, func(previous *IPFailureRecord) *IPFailureRecord {
		record := cloneIPFailureRecord(previous)
		if record == nil {
			now := time.Now()
			record = &IPFailureRecord{IP: ip, Events: []time.Time{}, FirstTime: now, LastTime: now}
		}
		if record.TriggerMinutes == 0 || record.TriggerCount == 0 || minutes < record.TriggerMinutes || minutes == record.TriggerMinutes && count < record.TriggerCount {
			record.TriggerMinutes = minutes
			record.TriggerCount = count
		}
		return record
	})
}
