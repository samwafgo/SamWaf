package ipset

import "sync/atomic"

// 威胁情报订阅"WAF 应用层"落地：全局单一并集(跨所有启用渠道)，对所有站点始终生效。
// 放在 ipset 这个叶子包，供 wafenginecore(判定读) 与 service(同步写) 共同引用，避免 import cycle。
// 用 atomic.Pointer 存放编译好的 MatchSet 成品，订阅任务在后台 goroutine 构建后一次指针替换发布，
// 请求热路径无锁读(RCU)。
var globalThreatMatcher atomic.Pointer[MatchSet]

// SetGlobalThreatMatcher 发布新的威胁情报并集(传 nil 表示清空)。由订阅服务调用。
func SetGlobalThreatMatcher(m *MatchSet) {
	globalThreatMatcher.Store(m)
}

// GetGlobalThreatMatcher 读取当前威胁情报并集(可能为 nil)。
func GetGlobalThreatMatcher() *MatchSet {
	return globalThreatMatcher.Load()
}
