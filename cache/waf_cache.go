package cache

import (
	"SamWaf/common/zlog"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

type WafCache struct {
	cache map[string]WafCacheItem
	mu    sync.Mutex
}
type WafCacheItem struct {
	value      interface{}
	createTime time.Time
	expireTime time.Time
	ttl        time.Duration
}

func InitWafCache() *WafCache {
	wafcache := &WafCache{
		cache: make(map[string]WafCacheItem),
		mu:    sync.Mutex{},
	}
	go wafcache.ClearExpirationCacheRoutine()
	return wafcache
}
func (wafCache *WafCache) Set(key string, value interface{}) {
	wafCache.SetWithTTl(key, value, 100*365*24*time.Hour)
}

// SetWithTTl 写入并设置存活时长。
//
// 注意语义（踩过坑，别再改回去）：对**已存在**的 key 会沿用原 createTime，
// 即到期时刻 = 原 createTime + 新 ttl，而不是 now + ttl。所以它只适合
// "首次写入" 或 "刷新值但不想改变到期时刻" 的场景；凡是要"续命"的地方
// 一律用 SetWithTTlRenewTime，否则会把在线会话凭空缩短甚至当场判死
// （历史上改密续期就是这样让令牌立刻失效的）。
//
// 另需注意：Redis 后端(RedisCache.SetWithTTl)没有 createTime 概念，等价于 now + ttl。
// 两个后端在"已存在 key"上的行为并不一致，写业务代码时不要依赖该差异。
func (wafCache *WafCache) SetWithTTl(key string, value interface{}, ttl time.Duration) {
	wafCache.mu.Lock()
	defer wafCache.mu.Unlock()
	createTime := time.Now()
	item, found := wafCache.cache[key]

	if found {
		createTime = item.createTime
	}
	wafCache.cache[key] = WafCacheItem{
		value:      value,
		createTime: createTime,
		expireTime: createTime.Add(ttl),
		ttl:        ttl,
	}
}

// SetWithTTlRenewTime 并重置时间
func (wafCache *WafCache) SetWithTTlRenewTime(key string, value interface{}, ttl time.Duration) {
	wafCache.mu.Lock()
	defer wafCache.mu.Unlock()
	createTime := time.Now()

	wafCache.cache[key] = WafCacheItem{
		value:      value,
		createTime: createTime,
		expireTime: createTime.Add(ttl), // 计算过期时间
		ttl:        ttl,
	}
}
func (wafCache *WafCache) GetAs(key string, out interface{}) error {
	val := wafCache.Get(key)
	if val == nil {
		return ErrCacheMiss
	}
	b, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func (wafCache *WafCache) GetBytes(key string) ([]byte, error) {
	key1Value := wafCache.Get(key)
	if str, ok := key1Value.([]byte); ok {
		return str, nil
	}
	return nil, ErrCacheMiss
}
func (wafCache *WafCache) GetString(key string) (string, error) {
	key1Value := wafCache.Get(key)
	if str, ok := key1Value.(string); ok {
		return str, nil
	}
	return "", ErrCacheMiss
}
func (wafCache *WafCache) GetInt(key string) (int, error) {
	key1Value := wafCache.Get(key)
	if str, ok := key1Value.(int); ok {
		return str, nil
	}
	return -1, ErrCacheMiss
}
func (wafCache *WafCache) IsKeyExist(key string) bool {
	wafCache.mu.Lock()
	defer wafCache.mu.Unlock()
	item, found := wafCache.cache[key]
	if !found {
		return false
	}
	if time.Since(item.createTime) <= item.ttl {
		return true
	}
	delete(wafCache.cache, key)
	return false
}
// ExistsE 内存实现不会有后端故障，error 恒为 nil
func (wafCache *WafCache) ExistsE(key string) (bool, error) {
	return wafCache.IsKeyExist(key), nil
}

// GetAsEx 读取并续期。与 SetWithTTlRenewTime 一致，续期从当前时刻重新计时。
func (wafCache *WafCache) GetAsEx(key string, out interface{}, ttl time.Duration) error {
	wafCache.mu.Lock()
	item, found := wafCache.cache[key]
	if found && time.Since(item.createTime) > item.ttl {
		delete(wafCache.cache, key)
		found = false
	}
	if found && ttl > 0 {
		now := time.Now()
		wafCache.cache[key] = WafCacheItem{
			value:      item.value,
			createTime: now,
			expireTime: now.Add(ttl),
			ttl:        ttl,
		}
	}
	wafCache.mu.Unlock()

	if !found {
		return ErrCacheMiss
	}
	b, err := json.Marshal(item.value)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// Touch 只续期不取值
func (wafCache *WafCache) Touch(key string, ttl time.Duration) error {
	wafCache.mu.Lock()
	defer wafCache.mu.Unlock()
	item, found := wafCache.cache[key]
	if !found {
		return ErrCacheMiss
	}
	if time.Since(item.createTime) > item.ttl {
		delete(wafCache.cache, key)
		return ErrCacheMiss
	}
	if ttl > 0 {
		now := time.Now()
		wafCache.cache[key] = WafCacheItem{
			value:      item.value,
			createTime: now,
			expireTime: now.Add(ttl),
			ttl:        ttl,
		}
	}
	return nil
}

func (wafCache *WafCache) Get(key string) interface{} {
	wafCache.mu.Lock()
	defer wafCache.mu.Unlock()
	item, found := wafCache.cache[key]
	if !found {
		return nil
	}
	if time.Since(item.createTime) <= item.ttl {
		return item.value
	}
	delete(wafCache.cache, key)
	return nil
}

func (wafCache *WafCache) Remove(key string) interface{} {
	wafCache.mu.Lock()
	defer wafCache.mu.Unlock()
	_, found := wafCache.cache[key]
	if !found {
		return nil
	}
	delete(wafCache.cache, key)
	return nil
}
func (wafCache *WafCache) GetExpireTime(key string) (time.Time, error) {
	wafCache.mu.Lock()
	defer wafCache.mu.Unlock()
	item, found := wafCache.cache[key]
	if !found {
		return time.Time{}, ErrCacheMiss
	}
	if time.Since(item.createTime) <= item.ttl {
		return item.expireTime, nil
	}
	zlog.Debug("GetExpireTime CLEAR CACHE EXPIRE :" + key)
	delete(wafCache.cache, key)
	return time.Time{}, ErrCacheMiss
}
func (wafCache *WafCache) ClearExpirationCache() {
	wafCache.mu.Lock()
	defer wafCache.mu.Unlock()
	now := time.Now()
	for key, item := range wafCache.cache {
		if now.Sub(item.createTime) > item.ttl {
			zlog.Debug("ClearExpirationCache CLEAR CACHE EXPIRE :" + key)
			delete(wafCache.cache, key)
		}
	}
}
func (wafCache *WafCache) ClearExpirationCacheRoutine() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		wafCache.ClearExpirationCache()
	}
}

// ListAvailableKeys 列出所有可用的键和剩余时间
func (wafCache *WafCache) ListAvailableKeys() map[string]time.Duration {
	wafCache.mu.Lock()
	defer wafCache.mu.Unlock()
	now := time.Now()
	availableKeys := make(map[string]time.Duration)

	for key, item := range wafCache.cache {
		remainingTime := item.ttl - now.Sub(item.createTime)
		if remainingTime > 0 {
			availableKeys[key] = remainingTime
		} else {
			delete(wafCache.cache, key) // 删除过期项
		}
	}
	return availableKeys
}

// ListAvailableKeysWithPrefix 列出指定前缀的可用键和剩余时间
func (wafCache *WafCache) ListAvailableKeysWithPrefix(prefix string) map[string]time.Duration {
	wafCache.mu.Lock()
	defer wafCache.mu.Unlock()
	now := time.Now()
	availableKeys := make(map[string]time.Duration)

	for key, item := range wafCache.cache {
		if strings.HasPrefix(key, prefix) {
			remainingTime := item.ttl - now.Sub(item.createTime)
			if remainingTime > 0 {
				availableKeys[key] = remainingTime
			} else {
				delete(wafCache.cache, key) // 删除过期项
			}
		}
	}
	return availableKeys
}
