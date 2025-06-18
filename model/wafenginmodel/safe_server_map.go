package wafenginmodel

import (
	"SamWaf/innerbean"
	"sync"
)

// SafeServerMap 线程安全的ServerRunTime Map
type SafeServerMap struct {
	mu    sync.RWMutex
	items map[int]innerbean.ServerRunTime
}

// NewSafeServerMap 创建新的安全Map
func NewSafeServerMap() *SafeServerMap {
	return &SafeServerMap{
		items: make(map[int]innerbean.ServerRunTime),
	}
}

// Get 获取值
func (m *SafeServerMap) Get(key int) (innerbean.ServerRunTime, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.items[key]
	return val, ok
}

// Set 设置值
func (m *SafeServerMap) Set(key int, value innerbean.ServerRunTime) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = value
}

// Delete 删除值
func (m *SafeServerMap) Delete(key int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
}

// Range 遍历Map
func (m *SafeServerMap) Range(f func(key int, value innerbean.ServerRunTime) bool) {
	// 先获取所有数据的副本
	m.mu.RLock()
	copy := make(map[int]innerbean.ServerRunTime, len(m.items))
	for k, v := range m.items {
		copy[k] = v
	}
	m.mu.RUnlock()

	// 在副本上遍历，不持有锁
	for k, v := range copy {
		if !f(k, v) {
			break
		}
	}
}

// Len 获取Map长度
func (m *SafeServerMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}

// GetAll 获取所有值
func (m *SafeServerMap) GetAll() map[int]innerbean.ServerRunTime {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[int]innerbean.ServerRunTime, len(m.items))
	for k, v := range m.items {
		result[k] = v
	}
	return result
}

// Clear 清空Map
func (m *SafeServerMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = make(map[int]innerbean.ServerRunTime)
}
