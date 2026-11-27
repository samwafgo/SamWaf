package wafwebcache

import (
	"container/list"
	"net/http"
	"sync"
	"time"
)

// memoryEntry 是已提交 L2 对象的只读 L1 副本。
// global/local 分别挂到进程与站点 LRU；同一次删除必须同步维护两条链和字节计数。
type memoryEntry struct {
	meta          metadata
	body          []byte
	scope         string
	cost          int64
	global, local *list.Element
}

// memoryCache 用一把锁保护索引、两级 LRU 和配额，避免并发淘汰造成计数漂移。
// 配额同时约束当前 Worker 总量与每站点总量；淘汰 L1 不回写，正文此前已提交到 L2。
type memoryCache struct {
	mu          sync.Mutex
	limit, used int64
	lru         *list.List
	entries     map[string]*memoryEntry
	byBase      map[string]map[string]*memoryEntry
	scopes      map[string]*list.List
	scopeBytes  map[string]int64
}

// newMemoryCache 创建独立 L1 实例，limit 的单位为字节。
func newMemoryCache(limit int64) *memoryCache {
	return &memoryCache{limit: limit, lru: list.New(), entries: map[string]*memoryEntry{}, byBase: map[string]map[string]*memoryEntry{}, scopes: map[string]*list.List{}, scopeBytes: map[string]int64{}}
}

// processMemory 由当前 Worker 的所有站点共享，滚动重启中的其他 Worker 另行计量。
var processMemory = newMemoryCache(256 * mib)

// memoryCost 把正文、响应头、键和条目估算开销一并计入配额；该值不是进程 RSS。
func memoryCost(meta metadata, bodyBytes int64) int64 {
	return bodyBytes + int64(meta.headerSize()+len(meta.Base)+len(meta.Key)) + 256
}

// fitsL1 在分配热对象缓冲前检查单对象预算，总量预算由 put 再次约束。
func fitsL1(meta metadata, s settings) bool {
	return meta.Size >= 0 && memoryCost(meta, meta.Size) <= s.L1ObjectBytes
}

// ConfigureL1Capacity 设置当前 Worker 的 L1 总字节数；缩小时立即按 LRU 淘汰。
// 非正值恢复有限默认容量，不能借此把缓存切成无限容量。
func ConfigureL1Capacity(bytes int64) {
	if bytes <= 0 {
		bytes = 256 * mib
	}
	processMemory.mu.Lock()
	defer processMemory.mu.Unlock()
	processMemory.limit = bytes
	for processMemory.used > bytes {
		processMemory.remove(processMemory.lru.Back().Value.(*memoryEntry))
	}
}

// remove 同步移除全部索引和配额记录；调用者必须持有 c.mu，不能在此重入加锁。
func (c *memoryCache) remove(e *memoryEntry) {
	delete(c.entries, e.meta.Key)
	delete(c.byBase[e.meta.Base], e.meta.Key)
	if len(c.byBase[e.meta.Base]) == 0 {
		delete(c.byBase, e.meta.Base)
	}
	c.lru.Remove(e.global)
	c.scopes[e.scope].Remove(e.local)
	c.used -= e.cost
	c.scopeBytes[e.scope] -= e.cost
	if c.scopes[e.scope].Len() == 0 {
		delete(c.scopes, e.scope)
		delete(c.scopeBytes, e.scope)
	}
}

// get 仅返回未过期且 Vary 匹配的副本，命中只刷新 LRU，不续内容 TTL。
// 返回的 metadata/Header/body 属于共享只读快照，调用方不得原地修改。
func (c *memoryCache) get(base string, h http.Header, now time.Time) (metadata, []byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.byBase[base] {
		if now.UnixNano() >= e.meta.Expires {
			c.remove(e)
			continue
		}
		if e.meta.Key != variantKey(base, e.meta.Vary, h) {
			continue
		}
		c.lru.MoveToFront(e.global)
		c.scopes[e.scope].MoveToFront(e.local)
		return e.meta, e.body, true
	}
	return metadata{}, nil, false
}

// put 先收回旧副本，再依次满足站点与进程配额；大于任一总预算的对象不进入 L1。
// 正文复制后归缓存所有，防止上游缓冲复用改变已缓存内容；调用前必须已成功提交 L2。
func (c *memoryCache) put(scope string, quota int64, meta metadata, body []byte) {
	cost := memoryCost(meta, int64(len(body)))
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.entries[meta.Key]; old != nil {
		c.remove(old)
	}
	if cost > quota || cost > c.limit || meta.Expires <= time.Now().UnixNano() {
		return
	}
	for c.scopeBytes[scope]+cost > quota {
		c.remove(c.scopes[scope].Back().Value.(*memoryEntry))
	}
	for c.used+cost > c.limit {
		c.remove(c.lru.Back().Value.(*memoryEntry))
	}
	if c.scopes[scope] == nil {
		c.scopes[scope] = list.New()
	}
	e := &memoryEntry{meta: meta, body: append([]byte(nil), body...), scope: scope, cost: cost}
	e.global = c.lru.PushFront(e)
	e.local = c.scopes[scope].PushFront(e)
	c.entries[meta.Key] = e
	if c.byBase[meta.Base] == nil {
		c.byBase[meta.Base] = map[string]*memoryEntry{}
	}
	c.byBase[meta.Base][meta.Key] = e
	c.used += cost
	c.scopeBytes[scope] += cost
}

// purge 删除同一基础键的全部 Vary 变体，用于源站拒绝续期及磁盘回收后的失效。
func (c *memoryCache) purge(base string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.byBase[base] {
		c.remove(e)
	}
}

// usage 在锁内获取一致的字节数与条目数，供诊断读取，不遍历或输出缓存内容。
func (c *memoryCache) usage() (int64, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.used, len(c.entries)
}

// heatSlot 记录从首次计数开始的固定窗口；命中不会把 since 向后移动。
type heatSlot struct {
	key   string
	since time.Time
	hits  int
}

// heatCounter 固定使用 4096 个槽，避免按攻击者可控 URI 无界分配热度条目。
type heatCounter struct {
	mu    sync.Mutex
	slots [4096]heatSlot
}

// hit 按 native-tier 的固定窗口累计请求热度，每次请求只在入口调用一次。
// 槽碰撞只重置晋升提示；正文身份始终使用完整摘要，不能依赖热度槽做授权或限速。
func (h *heatCounter) hit(key string, threshold int, window time.Duration, now time.Time) bool {
	index := 0
	for i := 0; i < 8 && i < len(key); i++ {
		index = (index*31 + int(key[i])) & 4095
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &h.slots[index]
	if s.key != key || now.Sub(s.since) >= window {
		*s = heatSlot{key: key, since: now}
	}
	if s.hits < 1000000 {
		s.hits++
	}
	return s.hits >= threshold
}
