package webplugin

import (
	"SamWaf/utils"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// LimitMode 限流模式
type LimitMode int

const (
	// RateMode 平均速率模式 - 每秒固定速率
	RateMode LimitMode = iota
	// WindowMode 滑动窗口模式 - N秒内最多M次
	WindowMode
)

// IPRateLimiter .
type IPRateLimiter struct {
	ips      map[string]*rate.Limiter
	mu       *sync.RWMutex
	r        rate.Limit
	b        int
	mode     LimitMode
	window   int                    // 时间窗口大小(秒)
	requests map[string][]time.Time // 用于滑动窗口模式记录请求时间
	Rule     *utils.RuleHelper
}

// NewIPRateLimiter 创建一个新的IP限流器
// r: 每秒请求速率
// b: 突发请求数量
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	i := &IPRateLimiter{
		ips:      make(map[string]*rate.Limiter),
		mu:       &sync.RWMutex{},
		r:        r,
		b:        b,
		mode:     RateMode, // 默认使用平均速率模式，保持向后兼容
		requests: make(map[string][]time.Time),
	}

	return i
}

// NewWindowIPRateLimiter 创建一个基于滑动窗口的IP限流器
// window: 时间窗口大小(秒)
// maxRequests: 窗口内最大请求数
func NewWindowIPRateLimiter(window, maxRequests int) *IPRateLimiter {
	i := &IPRateLimiter{
		ips:      make(map[string]*rate.Limiter),
		mu:       &sync.RWMutex{},
		r:        rate.Limit(float64(maxRequests) / float64(window)), // 保持兼容
		b:        maxRequests,
		mode:     WindowMode,
		window:   window,
		requests: make(map[string][]time.Time),
	}

	return i
}

// AddIP creates a new rate limiter and adds it to the ips map,
// using the IP address as the key
func (i *IPRateLimiter) AddIP(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter := rate.NewLimiter(i.r, i.b)

	i.ips[ip] = limiter
	i.requests[ip] = []time.Time{}

	return limiter
}

// GetLimiter returns the rate limiter for the provided IP address if it exists.
// Otherwise calls AddIP to add IP address to the map
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	limiter, exists := i.ips[ip]

	if !exists {
		i.mu.Unlock()
		return i.AddIP(ip)
	}

	i.mu.Unlock()

	return limiter
}

// Allow 检查是否允许请求通过
// 根据模式使用不同的限流策略
func (i *IPRateLimiter) Allow(ip string) bool {
	if i.mode == RateMode {
		// 使用令牌桶算法限流
		return i.GetLimiter(ip).Allow()
	} else {
		// 使用滑动窗口算法限流
		return i.allowByWindow(ip)
	}
}

// allowByWindow 使用滑动窗口算法检查是否允许请求通过
func (i *IPRateLimiter) allowByWindow(ip string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Duration(i.window) * time.Second)

	// 如果IP不存在，初始化
	if _, exists := i.requests[ip]; !exists {
		i.requests[ip] = []time.Time{}
	}

	// 清理过期的请求记录
	var validRequests []time.Time
	for _, t := range i.requests[ip] {
		if t.After(windowStart) { // 修改：添加Equal条件，确保边界值也被包含|| t.Equal(windowStart)
			validRequests = append(validRequests, t)
		}
	}

	// 检查是否超过限制
	if len(validRequests) >= i.b {
		i.requests[ip] = validRequests
		return false
	}

	// 记录新请求
	i.requests[ip] = append(validRequests, now)
	return true
}

// CleanupOldRecords 清理过期的请求记录
func (i *IPRateLimiter) CleanupOldRecords() {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Duration(i.window) * time.Second)

	for ip, times := range i.requests {
		var validRequests []time.Time
		for _, t := range times {
			if t.After(windowStart) {
				validRequests = append(validRequests, t)
			}
		}

		if len(validRequests) == 0 {
			delete(i.requests, ip)
			delete(i.ips, ip)
		} else {
			i.requests[ip] = validRequests
		}
	}
}

// ClearWindowForIP 清空指定IP的滑动窗口记录
// 用于手动重置某个IP的限流状态
func (i *IPRateLimiter) ClearWindowForIP(ip string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// 清空滑动窗口记录
	if _, exists := i.requests[ip]; exists {
		i.requests[ip] = []time.Time{}
	}

	// 重置令牌桶（用于平均速率模式）
	if _, exists := i.ips[ip]; exists {
		// 创建一个新的限流器替换旧的
		newLimiter := rate.NewLimiter(i.r, i.b)
		i.ips[ip] = newLimiter
	}
}

// GetRequestCount 获取指定IP在当前窗口内的请求数量
func (i *IPRateLimiter) GetRequestCount(ip string) int {
	i.mu.RLock()
	defer i.mu.RUnlock()

	now := time.Now()
	windowStart := now.Add(-time.Duration(i.window) * time.Second)

	if _, exists := i.requests[ip]; !exists {
		return 0
	}

	count := 0
	for _, t := range i.requests[ip] {
		if t.After(windowStart) || t.Equal(windowStart) {
			count++
		}
	}

	return count
}
