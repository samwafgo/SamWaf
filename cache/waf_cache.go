package cache

import (
	"errors"
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
	lastTime   time.Time
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
	wafCache.SetWithTTl(key, value, -1)
}

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
		lastTime:   time.Now(),
		ttl:        ttl,
	}
}
func (wafCache *WafCache) GetString(key string) (string, error) {
	key1Value := wafCache.Get(key)
	if str, ok := key1Value.(string); ok {
		return str, nil
	}
	return "", errors.New("数据不存在")
}
func (wafCache *WafCache) GetInt(key string) (int, error) {
	key1Value := wafCache.Get(key)
	if str, ok := key1Value.(int); ok {
		return str, nil
	}
	return -1, errors.New("数据不存在")
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
func (wafCache *WafCache) GetLastTime(key string) (time.Time, error) {
	wafCache.mu.Lock()
	defer wafCache.mu.Unlock()
	item, found := wafCache.cache[key]
	if !found {
		return time.Time{}, errors.New("数据不存在")
	}
	if time.Since(item.createTime) <= item.ttl {
		return item.lastTime, nil
	}
	delete(wafCache.cache, key)
	return time.Time{}, errors.New("数据已过期")
}
func (wafCache *WafCache) ClearExpirationCache() {
	now := time.Now()
	for key, item := range wafCache.cache {
		if now.Sub(item.createTime) > item.ttl {
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
