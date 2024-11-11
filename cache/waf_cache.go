package cache

import (
	"errors"
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
