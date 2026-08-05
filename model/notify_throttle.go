package model

import (
	"encoding/json"
	"strings"
)

/*
*
通知订阅的频率控制 / 过滤条件配置

设计要点（对应 issue #822）：
  - 所有字段的零值都表示「继承上层默认」，所以老库升级后不填任何东西，行为与升级前完全一致。
  - 频控细项放 JSON 而不是摊平成列：冷却梯度是数组、去重维度是集合，
    摊平会导致每加一个策略就要动一次表结构和一次迁移。
*/

// 频控模式
const (
	ThrottleModeInherit   = "inherit"   // 继承全局默认
	ThrottleModeRealtime  = "realtime"  // 直发，不做任何抑制
	ThrottleModeAggregate = "aggregate" // 时间窗口内合并成一条
	ThrottleModeCooldown  = "cooldown"  // 首条立即发，随后进入递增冷却
)

// 去重维度：决定频控 key 由哪些字段拼成
//
// 历史教训：老实现用「规则原文」当 key，攻击方变换 payload 就能让每条消息都算首次出现，
// 冷却完全失效（issue #822 里"只要有消息就发"的直接原因）。所以默认维度用域名+攻击类型这类
// 稳定字段，规则原文只作为可选项保留。
const (
	DedupKeyMessageType = "message_type"
	DedupKeyDomain      = "domain"
	DedupKeyIp          = "ip"
	DedupKeyRule        = "rule"
	DedupKeyAttackType  = "attack_type"
)

// 消息严重级别
const (
	SeverityInfo     = "info"
	SeverityWarn     = "warn"
	SeverityCritical = "critical"
)

// 抑制原因（写入 NotifyLog.SuppressReason，用于回答"为什么没收到"）
const (
	SuppressReasonCooldown   = "cooldown"    // 处于冷却期
	SuppressReasonRateLimit  = "rate_limit"  // 触发每小时上限
	SuppressReasonQuietHours = "quiet_hours" // 免打扰时段
	SuppressReasonFilterMiss = "filter_miss" // 过滤条件未命中
)

// 通知日志状态
const (
	NotifyLogStatusFail     = 0 // 发送失败
	NotifyLogStatusSuccess  = 1 // 发送成功
	NotifyLogStatusSuppress = 2 // 被抑制（未发送）
)

// 模板使用情况（写入 NotifyLog.TemplateUsed）
const (
	TemplateUsedDefault  = "default"         // 内置默认格式
	TemplateUsedCustom   = "custom"          // 自定义模板渲染成功
	TemplateUsedFallback = "custom_fallback" // 自定义模板渲染失败，已降级为默认格式
)

// 频控参数边界（同时用于 api 层入参校验和解析时的兜底裁剪）
const (
	ThrottleWindowMin      = 1
	ThrottleWindowMax      = 3600
	ThrottleCooldownMin    = 1
	ThrottleCooldownMax    = 86400
	ThrottleMaxDetailMin   = 1
	ThrottleMaxDetailMax   = 50
	ThrottleMaxPerHourMax  = 10000
	ThrottleCooldownSteps  = 5 // 冷却梯度最多几级
	ThrottleResetSecMax    = 86400
	NotifyTitleTemplateMax = 500
	NotifyBodyTemplateMax  = 8192
)

// NotifyThrottleConfig 订阅级频控细项，序列化后存 NotifySubscription.ThrottleJSON
type NotifyThrottleConfig struct {
	AggregateWindowSec       int      `json:"aggregate_window_sec"`        // 聚合窗口（秒），0=继承
	AggregateMaxDetail       int      `json:"aggregate_max_detail"`        // 合并通知里最多展示几条明细，0=继承
	CooldownStepsSec         []int    `json:"cooldown_steps_sec"`          // 递增冷却梯度（秒），空=继承
	CooldownResetSec         int      `json:"cooldown_reset_sec"`          // 多久无消息后冷却级别归零，0=继承
	MaxPerHour               int      `json:"max_per_hour"`                // 每小时最多发几条，0=不限
	DedupKeys                []string `json:"dedup_keys"`                  // 去重维度，空=继承
	QuietHours               string   `json:"quiet_hours"`                 // 免打扰时段 "23:00-07:00"，空=不启用
	QuietHoursBypassSeverity string   `json:"quiet_hours_bypass_severity"` // 该级别及以上穿透免打扰，空=不穿透
}

// NotifyFilterConfig 订阅级过滤条件，序列化后存 NotifySubscription.FilterJSON
//
// 全部为空表示不过滤（保持老行为）。keywords 只做包含匹配、不接受用户正则，避免 ReDoS。
type NotifyFilterConfig struct {
	Domains     []string `json:"domains"`      // 只发这些域名（支持 *.a.com），空=全部
	ExcludeIps  []string `json:"exclude_ips"`  // 这些 IP/CIDR 的事件不发
	Keywords    []string `json:"keywords"`     // 规则信息/攻击类型/URL 命中任一关键字才发，空=全部
	MinSeverity string   `json:"min_severity"` // 最低严重级别，空=不限
}

// ParseNotifyThrottleConfig 解析频控配置，任何异常都退回空配置（即"全部继承默认"），
// 保证一条脏数据不会让通知发不出去。
func ParseNotifyThrottleConfig(jsonStr string) NotifyThrottleConfig {
	var c NotifyThrottleConfig
	if strings.TrimSpace(jsonStr) == "" {
		return c
	}
	if err := json.Unmarshal([]byte(jsonStr), &c); err != nil {
		return NotifyThrottleConfig{}
	}
	return c.Sanitize()
}

// Sanitize 裁剪到合法区间，非法值一律归零（=继承默认）
func (c NotifyThrottleConfig) Sanitize() NotifyThrottleConfig {
	if c.AggregateWindowSec < ThrottleWindowMin || c.AggregateWindowSec > ThrottleWindowMax {
		c.AggregateWindowSec = 0
	}
	if c.AggregateMaxDetail < ThrottleMaxDetailMin || c.AggregateMaxDetail > ThrottleMaxDetailMax {
		c.AggregateMaxDetail = 0
	}
	if c.CooldownResetSec < 0 || c.CooldownResetSec > ThrottleResetSecMax {
		c.CooldownResetSec = 0
	}
	if c.MaxPerHour < 0 || c.MaxPerHour > ThrottleMaxPerHourMax {
		c.MaxPerHour = 0
	}

	steps := make([]int, 0, ThrottleCooldownSteps)
	for _, s := range c.CooldownStepsSec {
		if s < ThrottleCooldownMin || s > ThrottleCooldownMax {
			continue
		}
		steps = append(steps, s)
		if len(steps) >= ThrottleCooldownSteps {
			break
		}
	}
	c.CooldownStepsSec = steps

	keys := make([]string, 0, len(c.DedupKeys))
	for _, k := range c.DedupKeys {
		if IsValidDedupKey(k) && !containsStr(keys, k) {
			keys = append(keys, k)
		}
	}
	c.DedupKeys = keys

	if !IsValidQuietHours(c.QuietHours) {
		c.QuietHours = ""
	}
	if !IsValidSeverity(c.QuietHoursBypassSeverity) {
		c.QuietHoursBypassSeverity = ""
	}
	return c
}

// ParseNotifyFilterConfig 解析过滤条件；解析不了就当作"不过滤"，
// 宁可多发也不能因为一条脏配置把告警全吞掉。
func ParseNotifyFilterConfig(jsonStr string) NotifyFilterConfig {
	var c NotifyFilterConfig
	if strings.TrimSpace(jsonStr) == "" {
		return c
	}
	if err := json.Unmarshal([]byte(jsonStr), &c); err != nil {
		return NotifyFilterConfig{}
	}
	if !IsValidSeverity(c.MinSeverity) {
		c.MinSeverity = ""
	}
	return c
}

// IsEmpty 判断过滤条件是否完全没配（用于快速跳过过滤逻辑）
func (c NotifyFilterConfig) IsEmpty() bool {
	return len(c.Domains) == 0 && len(c.ExcludeIps) == 0 && len(c.Keywords) == 0 && c.MinSeverity == ""
}

// IsValidThrottleMode 校验频控模式
func IsValidThrottleMode(mode string) bool {
	switch mode {
	case ThrottleModeInherit, ThrottleModeRealtime, ThrottleModeAggregate, ThrottleModeCooldown:
		return true
	}
	return false
}

// IsValidDedupKey 校验去重维度
func IsValidDedupKey(key string) bool {
	switch key {
	case DedupKeyMessageType, DedupKeyDomain, DedupKeyIp, DedupKeyRule, DedupKeyAttackType:
		return true
	}
	return false
}

// IsValidSeverity 校验严重级别（空串合法，表示不限）
func IsValidSeverity(s string) bool {
	switch s {
	case "", SeverityInfo, SeverityWarn, SeverityCritical:
		return true
	}
	return false
}

// SeverityLevel 严重级别转数值，便于比较
func SeverityLevel(s string) int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityWarn:
		return 2
	default:
		return 1
	}
}

// IsValidQuietHours 校验免打扰时段格式 "HH:MM-HH:MM"（空串合法，表示不启用）
func IsValidQuietHours(s string) bool {
	if s == "" {
		return true
	}
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if !isValidHHMM(strings.TrimSpace(p)) {
			return false
		}
	}
	return true
}

func isValidHHMM(s string) bool {
	if len(s) != 5 || s[2] != ':' {
		return false
	}
	h := (int(s[0]-'0'))*10 + int(s[1]-'0')
	m := (int(s[3]-'0'))*10 + int(s[4]-'0')
	if s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9' || s[3] < '0' || s[3] > '9' || s[4] < '0' || s[4] > '9' {
		return false
	}
	return h >= 0 && h <= 23 && m >= 0 && m <= 59
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
