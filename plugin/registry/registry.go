package registry

import (
	"fmt"
	"sync"
)

// PluginInfo 插件注册信息
type PluginInfo struct {
	ID       string   // 插件ID
	Name     string   // 插件名称
	Type     string   // 插件类型
	Version  string   // 插件版本
	Priority int      // 优先级
	Groups   []string // 所属分组
	Enabled  bool     // 是否启用
}

// Registry 插件注册表
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]*PluginInfo // key: plugin ID
}

// NewRegistry 创建插件注册表
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]*PluginInfo),
	}
}

// Register 注册插件
func (r *Registry) Register(info *PluginInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.plugins[info.ID]; exists {
		return fmt.Errorf("plugin already registered: %s", info.ID)
	}

	r.plugins[info.ID] = info
	return nil
}

// Unregister 注销插件
func (r *Registry) Unregister(pluginID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.plugins[pluginID]; !exists {
		return fmt.Errorf("plugin not found: %s", pluginID)
	}

	delete(r.plugins, pluginID)
	return nil
}

// Get 获取插件信息
func (r *Registry) Get(pluginID string) (*PluginInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, exists := r.plugins[pluginID]
	if !exists {
		return nil, fmt.Errorf("plugin not found: %s", pluginID)
	}

	return info, nil
}

// GetByGroup 获取指定分组的所有插件
func (r *Registry) GetByGroup(group string) []*PluginInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*PluginInfo
	for _, info := range r.plugins {
		if info.Enabled && contains(info.Groups, group) {
			result = append(result, info)
		}
	}

	return result
}

// GetAll 获取所有插件信息
func (r *Registry) GetAll() []*PluginInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*PluginInfo, 0, len(r.plugins))
	for _, info := range r.plugins {
		result = append(result, info)
	}

	return result
}

// contains 检查字符串是否在切片中
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
