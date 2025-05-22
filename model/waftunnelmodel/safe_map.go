package waftunnelmodel

import (
	"sync"
)

// SafeTunnelMap 线程安全的TunnelTarget Map
type SafeTunnelMap struct {
	mu    sync.RWMutex
	items map[string]*TunnelSafe
}

// NewSafeTunnelMap 创建新的安全Map
func NewSafeTunnelMap() *SafeTunnelMap {
	return &SafeTunnelMap{
		items: make(map[string]*TunnelSafe),
	}
}

// Get 获取值
func (m *SafeTunnelMap) Get(key string) (*TunnelSafe, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.items[key]
	return val, ok
}

// Set 设置值
func (m *SafeTunnelMap) Set(key string, value *TunnelSafe) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = value
}

// Delete 删除值
func (m *SafeTunnelMap) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
}

// Range 遍历Map
func (m *SafeTunnelMap) Range(f func(key string, value *TunnelSafe) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for k, v := range m.items {
		if !f(k, v) {
			break
		}
	}
}

// Len 获取Map长度
func (m *SafeTunnelMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}

// GetAll 获取所有值
func (m *SafeTunnelMap) GetAll() map[string]*TunnelSafe {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]*TunnelSafe, len(m.items))
	for k, v := range m.items {
		result[k] = v
	}
	return result
}
func (m *SafeTunnelMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = make(map[string]*TunnelSafe)
}

// SafeNetMap 线程安全的NetListerOnline Map
type SafeNetMap struct {
	mu    sync.RWMutex
	items map[string]NetRunTime
}

// NewSafeNetMap 创建新的安全Map
func NewSafeNetMap() *SafeNetMap {
	return &SafeNetMap{
		items: make(map[string]NetRunTime),
	}
}

// Get 获取值
func (m *SafeNetMap) Get(key string) (NetRunTime, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	val, ok := m.items[key]
	return val, ok
}

// Set 设置值
func (m *SafeNetMap) Set(key string, value NetRunTime) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = value
}

// Delete 删除值
func (m *SafeNetMap) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
}

// Range 遍历Map
func (m *SafeNetMap) Range(f func(key string, value NetRunTime) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for k, v := range m.items {
		if !f(k, v) {
			break
		}
	}
}

// Len 获取Map长度
func (m *SafeNetMap) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}

// GetAll 获取所有值
func (m *SafeNetMap) GetAll() map[string]NetRunTime {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]NetRunTime, len(m.items))
	for k, v := range m.items {
		result[k] = v
	}
	return result
}
func (m *SafeNetMap) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = make(map[string]NetRunTime)
}
