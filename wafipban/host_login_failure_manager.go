package wafipban

import (
	"SamWaf/cache"
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"time"
)

// 主机远程登录(SSH/RDP)失败计数器。
//
// 与同包的 IPFailureManager 算法同构，但**刻意不共用 keyspace**：
// IPFailureManager 的计数会被自定义规则属性 MF.GetIPFailureCount(minutes) 读取
// (见 model/rule_grl_safe.go 的 ruleAttrFailCountRegex)，把 SSH/RDP 的登录失败
// 混进去，用户已经写好的 HTTP 规则语义就被静默改掉了——一个只爆破 SSH、从没碰过
// Web 的 IP 会让 `MF.GetIPFailureCount(5) > 10` 这类规则命中。
// 所以这里只共用 cache.CacheStore 与滑动窗口算法，键前缀完全独立。

// HostLoginFailureRecord 某个 (来源, IP) 的失败事件滑动窗口
type HostLoginFailureRecord struct {
	Source    string
	IP        string
	Events    []time.Time
	Count     int64
	FirstTime time.Time
	LastTime  time.Time
}

// HostLoginFailureManager 主机登录失败计数器
type HostLoginFailureManager struct {
	cache cache.CacheStore
}

var hostLoginFailureManagerInstance *HostLoginFailureManager

// InitHostLoginFailureManager 初始化单例，复用与 InitIPBanManager 相同的 CacheStore
func InitHostLoginFailureManager(wafCache cache.CacheStore) {
	if hostLoginFailureManagerInstance != nil {
		return
	}
	hostLoginFailureManagerInstance = &HostLoginFailureManager{cache: wafCache}
}

// GetHostLoginFailureManager 获取单例，未初始化时返回 nil(调用方需判空)
func GetHostLoginFailureManager() *HostLoginFailureManager {
	if hostLoginFailureManagerInstance == nil {
		zlog.Error("HostLoginFailureManager 未初始化，请先调用 InitHostLoginFailureManager")
	}
	return hostLoginFailureManagerInstance
}

// hostLoginKey 计数键：来源与 IP 分开计数，SSH 爆破不会把 RDP 的额度用掉
func hostLoginKey(source, ip string) string {
	return enums.CACHE_HOST_LOGIN_FAIL_PRE + source + ":" + ip
}

// Record 记录一次失败并返回窗口内累计次数。
// 一次调用完成"读-改-写"，调用方不需要再单独 GetCount，少一次缓存往返。
// retentionMinutes 是事件保留窗口，取 max(统计窗口, 封禁时长)，保证解封后
// 仍能看到历史(用于展示)，但又不会无限增长。
func (m *HostLoginFailureManager) Record(source, ip string, windowMinutes, retentionMinutes int64) int64 {
	if m == nil || ip == "" {
		return 0
	}
	if windowMinutes <= 0 {
		windowMinutes = 10
	}
	if retentionMinutes < windowMinutes {
		retentionMinutes = windowMinutes
	}

	key := hostLoginKey(source, ip)
	now := time.Now()

	var record *HostLoginFailureRecord
	if val := m.cache.Get(key); val != nil {
		if r, ok := val.(*HostLoginFailureRecord); ok {
			record = r
		}
	}
	if record == nil {
		record = &HostLoginFailureRecord{
			Source:    source,
			IP:        ip,
			Events:    []time.Time{},
			FirstTime: now,
		}
	}

	record.Events = append(record.Events, now)

	// 按保留窗口裁剪，同时统计落在统计窗口内的次数
	retentionStart := now.Add(-time.Duration(retentionMinutes) * time.Minute)
	windowStart := now.Add(-time.Duration(windowMinutes) * time.Minute)
	valid := make([]time.Time, 0, len(record.Events))
	var inWindow int64
	for _, t := range record.Events {
		if t.After(retentionStart) {
			valid = append(valid, t)
			if t.After(windowStart) {
				inWindow++
			}
		}
	}
	record.Events = valid
	record.Count = int64(len(valid))
	if len(valid) > 0 {
		record.FirstTime = valid[0]
	}
	record.LastTime = now

	m.cache.SetWithTTlRenewTime(key, record, time.Duration(retentionMinutes)*time.Minute)
	return inWindow
}

// GetCount 查询窗口内失败次数(不写入)
func (m *HostLoginFailureManager) GetCount(source, ip string, windowMinutes int64) int64 {
	if m == nil || ip == "" {
		return 0
	}
	val := m.cache.Get(hostLoginKey(source, ip))
	if val == nil {
		return 0
	}
	record, ok := val.(*HostLoginFailureRecord)
	if !ok {
		return 0
	}
	windowStart := time.Now().Add(-time.Duration(windowMinutes) * time.Minute)
	var cnt int64
	for _, t := range record.Events {
		if t.After(windowStart) {
			cnt++
		}
	}
	return cnt
}

// Clear 清除计数。封禁下发后调用，避免解封瞬间旧事件仍在窗口内导致立刻二次封禁。
func (m *HostLoginFailureManager) Clear(source, ip string) {
	if m == nil || ip == "" {
		return
	}
	m.cache.Remove(hostLoginKey(source, ip))
}

// GetRecord 取原始记录(展示/调试用)
func (m *HostLoginFailureManager) GetRecord(source, ip string) *HostLoginFailureRecord {
	if m == nil || ip == "" {
		return nil
	}
	val := m.cache.Get(hostLoginKey(source, ip))
	if val == nil {
		return nil
	}
	record, _ := val.(*HostLoginFailureRecord)
	return record
}
