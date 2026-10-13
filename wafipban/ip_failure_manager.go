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

// RecordFailure 记录IP失败
func (m *IPFailureManager) RecordFailure(webLog *innerbean.WebLog) {
	if webLog == nil || webLog.SRC_IP == "" || global.GCONFIG_IP_FAILURE_BAN_ENABLED == 0 {
		return
	}

	// 如果是bot且危险程度是0，不记录失败
	if webLog.IsBot == 1 && webLog.RISK_LEVEL == 0 {
		return
	}

	// 如果是证书申请路径，不记录失败
	if strings.HasPrefix(webLog.URL, global.GSSL_HTTP_CHANGLE_PATH) {
		return
	}

	ip := webLog.SRC_IP
	key := enums.CACHE_IP_FAILURE_PRE + ip
	now := time.Now()

	// 读-改-写整体互斥：日志协程(本函数)与请求路径(RecordFailureThreshold)
	// 会并发交错，不加锁后写者会整份覆盖先写者，丢阈值戳或失败事件
	m.mu.Lock()
	defer m.mu.Unlock()

	// 获取现有记录（克隆副本再改，缓存里的快照保持不可变）
	record := cloneIPFailureRecord(m.load(ip))
	if record == nil {
		record = &IPFailureRecord{
			IP:        ip,
			Events:    []time.Time{},
			FirstTime: now,
			LastTime:  now,
		}
	}
	// 记录事件
	record.Events = append(record.Events, now)
	// 清理过期事件（按封锁时间作为保留窗口）
	retention := time.Duration(global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME) * time.Minute
	windowStart := now.Add(-retention)
	var valid []time.Time
	for _, t := range record.Events {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}
	record.Events = valid
	record.Count = int64(len(record.Events))
	if len(record.Events) > 0 {
		record.FirstTime = record.Events[0]
	}
	record.LastTime = now

	// 保存到缓存，TTL设置为封锁时间
	ttl := time.Duration(global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME) * time.Minute
	m.cache.SetWithTTlRenewTime(key, record, ttl)
}

// GetFailureCount 获取IP在指定时间窗口内的失败次数
// minutes: 时间窗口（分钟）
func (m *IPFailureManager) GetFailureCount(ip string, minutes int64) int64 {
	if ip == "" || global.GCONFIG_IP_FAILURE_BAN_ENABLED == 0 {
		return 0
	}

	// 只读快照，RLock 即可：规则引擎每条命中规则的请求都会求值一次
	m.mu.RLock()
	defer m.mu.RUnlock()
	record := m.load(ip)
	if record == nil {
		return 0
	}

	now := time.Now()
	windowStart := now.Add(-time.Duration(minutes) * time.Minute)
	cnt := int64(0)
	for _, t := range record.Events {
		if t.After(windowStart) {
			cnt++
		}
	}
	return cnt
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

// RecordFailureThreshold 记录IP失败封禁的阈值信息（当规则匹配时调用）
// ip: IP地址
// minutes: 触发封禁的时间窗口（分钟）
// count: 触发封禁的失败次数阈值
func (m *IPFailureManager) RecordFailureThreshold(ip string, minutes int64, count int64) {
	if ip == "" || global.GCONFIG_IP_FAILURE_BAN_ENABLED == 0 {
		return
	}

	key := enums.CACHE_IP_FAILURE_PRE + ip

	m.mu.Lock()
	defer m.mu.Unlock()

	record := cloneIPFailureRecord(m.load(ip))
	if record == nil {
		// 记录不存在：新建一条并盖上阈值戳
		record = &IPFailureRecord{
			IP:             ip,
			Events:         []time.Time{},
			TriggerMinutes: minutes,
			TriggerCount:   count,
			FirstTime:      time.Now(),
			LastTime:       time.Now(),
		}
	} else if record.TriggerMinutes == 0 || record.TriggerCount == 0 {
		record.TriggerMinutes = minutes
		record.TriggerCount = count
	} else if minutes < record.TriggerMinutes || (minutes == record.TriggerMinutes && count < record.TriggerCount) {
		// 新的阈值更严格（时间窗口更小或次数更少）则更新
		record.TriggerMinutes = minutes
		record.TriggerCount = count
	}

	// 保存记录
	ttl := time.Duration(global.GCONFIG_IP_FAILURE_BAN_LOCK_TIME) * time.Minute
	m.cache.SetWithTTlRenewTime(key, record, ttl)
}
