// Package cccounter 是 CC 防护的请求计数器。
//
// 它替代了原先「每个 IP 存一份时间戳切片、全局一把锁」的做法——那种结构在被 CC 打时
// 自己就是瓶颈：每请求 O(n) 遍历加一次切片分配，且客户端数量没有上限。
//
// 这里用固定桶数的近似滑动窗口：
//   - 每个计数键固定 numBuckets 个计数桶，桶宽 = 窗口 / numBuckets；
//   - 写入时按当前时间片轮转清零，读取时求和；
//   - 每个键的内存占用是常量，每次请求的开销是 O(numBuckets) 且不分配。
//
// 代价是精度：窗口边界最多有一个桶宽的误差（默认 10%）。这与 AWS WAF 对
// 滚动窗口「近似」的取舍一致——精确到毫秒的代价换不来防护效果的提升。
package cccounter

import (
	"hash/fnv"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// numBuckets 每个计数键的桶数。10 个桶意味着窗口边界误差不超过 10%。
	numBuckets = 10
	// shardCount 分片数，取 2 的幂便于用位运算取模。
	// 分片的意义是把锁竞争打散：CC 攻击下所有请求挤在一把锁上，防御模块自己会成为瓶颈。
	shardCount = 64
	shardMask  = shardCount - 1

	// maxDimValueLen 统计维度取值参与计算前的截断长度。
	// 维度取值可能来自请求头/Cookie/查询参数，完全由客户端控制，必须先限长再哈希。
	maxDimValueLen = 128

	// defaultMaxKeys 计数键总数上限。
	// 这是被 CC 打时 WAF 自身的存活线：分布式攻击下客户端数量可以无限增长，
	// 没有上限就等于把防护模块变成内存耗尽的入口。
	defaultMaxKeys = 200000
	// defaultRuleQuota 单条规则的计数键配额。
	// 超配额说明该规则的统计维度基数失控（典型是拿可伪造的请求头当维度），
	// 此时该规则降级为按 IP 统计，而不是继续吃内存。
	defaultRuleQuota = 50000
)

// bucketRing 一个计数键的环形计数桶。
type bucketRing struct {
	counts   [numBuckets]int32
	slot     int64 // 最近一次写入所处的时间片序号
	lastSeen int64 // 最近活跃时间(unix 秒)，供淘汰使用
	ruleID   string
}

type shard struct {
	mu   sync.Mutex
	keys map[string]*bucketRing
}

// Counter 进程内分片计数器。
type Counter struct {
	shards [shardCount]*shard

	metaMu   sync.Mutex
	ruleKeys map[string]int // 每条规则当前占用的计数键数量

	totalKeys int64 // 原子读写，供无锁快速判断与诊断展示
	maxKeys   int64
	ruleQuota int

	degradedCount int64 // 因维度基数超限而降级的次数
	evictedCount  int64 // 被淘汰的键数量
	rejectedCount int64 // 因总量上限被拒绝新建的次数

	nowFn func() time.Time // 便于测试注入时间
}

// New 创建计数器。maxKeys / ruleQuota 传 0 时使用默认值。
func New(maxKeys int64, ruleQuota int) *Counter {
	if maxKeys <= 0 {
		maxKeys = defaultMaxKeys
	}
	if ruleQuota <= 0 {
		ruleQuota = defaultRuleQuota
	}
	c := &Counter{
		ruleKeys:  make(map[string]int),
		maxKeys:   maxKeys,
		ruleQuota: ruleQuota,
		nowFn:     time.Now,
	}
	for i := 0; i < shardCount; i++ {
		c.shards[i] = &shard{keys: make(map[string]*bucketRing)}
	}
	return c
}

// buildKey 由规则与维度取值拼出计数键。
//
// 维度取值先截断再哈希成定长十六进制：
//   - 哈希后长度固定且不含分隔符，拼接不可能被取值里的字符串串到别的规则上；
//   - 同时避免把 Cookie、Authorization 这类可能是凭据的原文留在内存里当作键。
func buildKey(ruleID, dimValue string) string {
	if len(dimValue) > maxDimValueLen {
		dimValue = dimValue[:maxDimValueLen]
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(dimValue))
	return ruleID + ":" + strconv.FormatUint(h.Sum64(), 16)
}

func shardFor(key string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32()) & shardMask
}

// Result 一次计数的结果。
type Result struct {
	Count    int64 // 当前窗口内的计数（含本次）
	Degraded bool  // 该规则的维度基数超限，调用方应改用 IP 维度重试
	Rejected bool  // 计数键总量已达上限，本次未计数
}

// Incr 累加一次并返回窗口内计数。
//
// dimValue 为空时调用方必须先回退到别的维度再调用：把取不到维度值的请求全归到同一个键，
// 会让所有「没带这个字段」的正常访客共用一个计数桶，一起被限死。
func (c *Counter) Incr(ruleID, dimValue string, windowSec int) Result {
	if windowSec <= 0 {
		windowSec = 1
	}
	bucketWidth := windowSec / numBuckets
	if bucketWidth <= 0 {
		bucketWidth = 1
	}

	key := buildKey(ruleID, dimValue)
	sh := c.shards[shardFor(key)]
	now := c.nowFn().Unix()
	slot := now / int64(bucketWidth)

	sh.mu.Lock()
	ring, exists := sh.keys[key]
	if !exists {
		if !c.reserveKey(ruleID) {
			sh.mu.Unlock()
			// 区分两种拒绝：规则内基数失控可降级重试，总量到顶只能放弃本次计数
			if atomic.LoadInt64(&c.totalKeys) >= atomic.LoadInt64(&c.maxKeys) {
				return Result{Rejected: true}
			}
			return Result{Degraded: true}
		}
		ring = &bucketRing{slot: slot, ruleID: ruleID}
		sh.keys[key] = ring
	}

	// 时间片推进：把跨过的桶清零。跨度超过桶数时整圈清零即可。
	if delta := slot - ring.slot; delta > 0 {
		if delta >= numBuckets {
			for i := range ring.counts {
				ring.counts[i] = 0
			}
		} else {
			for i := int64(1); i <= delta; i++ {
				ring.counts[(ring.slot+i)%numBuckets] = 0
			}
		}
		ring.slot = slot
	}
	ring.counts[slot%numBuckets]++
	ring.lastSeen = now

	var sum int64
	for _, v := range ring.counts {
		sum += int64(v)
	}
	sh.mu.Unlock()

	return Result{Count: sum}
}

// reserveKey 为新键占一个名额。返回 false 表示达到规则配额或全局上限。
// 调用方持有 shard 锁；本方法只取 metaMu，锁顺序固定为 shard -> meta，不会形成环。
func (c *Counter) reserveKey(ruleID string) bool {
	if atomic.LoadInt64(&c.totalKeys) >= atomic.LoadInt64(&c.maxKeys) {
		atomic.AddInt64(&c.rejectedCount, 1)
		return false
	}
	c.metaMu.Lock()
	defer c.metaMu.Unlock()
	if c.ruleKeys[ruleID] >= c.ruleQuota {
		atomic.AddInt64(&c.degradedCount, 1)
		return false
	}
	c.ruleKeys[ruleID]++
	atomic.AddInt64(&c.totalKeys, 1)
	return true
}

func (c *Counter) releaseKey(ruleID string) {
	c.metaMu.Lock()
	if n := c.ruleKeys[ruleID]; n <= 1 {
		delete(c.ruleKeys, ruleID)
	} else {
		c.ruleKeys[ruleID] = n - 1
	}
	c.metaMu.Unlock()
	atomic.AddInt64(&c.totalKeys, -1)
	atomic.AddInt64(&c.evictedCount, 1)
}

// Cleanup 回收空闲超过 idleSeconds 的计数键。由定时任务驱动。
func (c *Counter) Cleanup(idleSeconds int64) int {
	if idleSeconds <= 0 {
		idleSeconds = 300
	}
	cutoff := c.nowFn().Unix() - idleSeconds
	removed := 0
	for _, sh := range c.shards {
		sh.mu.Lock()
		for key, ring := range sh.keys {
			if ring.lastSeen <= cutoff {
				delete(sh.keys, key)
				c.releaseKey(ring.ruleID)
				removed++
			}
		}
		sh.mu.Unlock()
	}
	return removed
}

// DropRule 删除某条规则的全部计数键，用于规则被删除或停用时立即释放内存。
func (c *Counter) DropRule(ruleID string) {
	for _, sh := range c.shards {
		sh.mu.Lock()
		for key, ring := range sh.keys {
			if ring.ruleID == ruleID {
				delete(sh.keys, key)
				c.releaseKey(ring.ruleID)
			}
		}
		sh.mu.Unlock()
	}
}

// Reset 清空全部计数，仅用于测试与手工重置。
func (c *Counter) Reset() {
	for _, sh := range c.shards {
		sh.mu.Lock()
		sh.keys = make(map[string]*bucketRing)
		sh.mu.Unlock()
	}
	c.metaMu.Lock()
	c.ruleKeys = make(map[string]int)
	c.metaMu.Unlock()
	atomic.StoreInt64(&c.totalKeys, 0)
}

// Stats 当前计量值，供运行诊断展示。内存读取级别，不做任何 IO。
func (c *Counter) Stats() map[string]int64 {
	c.metaMu.Lock()
	rules := int64(len(c.ruleKeys))
	c.metaMu.Unlock()
	return map[string]int64{
		"active_keys":    atomic.LoadInt64(&c.totalKeys),
		"max_keys":       atomic.LoadInt64(&c.maxKeys),
		"tracked_rules":  rules,
		"degraded_count": atomic.LoadInt64(&c.degradedCount),
		"evicted_count":  atomic.LoadInt64(&c.evictedCount),
		"rejected_count": atomic.LoadInt64(&c.rejectedCount),
	}
}

// ActiveKeys 当前计数键总数。
func (c *Counter) ActiveKeys() int64 { return atomic.LoadInt64(&c.totalKeys) }
