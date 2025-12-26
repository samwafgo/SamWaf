package plugininterface

import (
	"context"
)

// Plugin 基础插件接口
type Plugin interface {
	// Name 返回插件名称
	Name() string

	// Version 返回插件版本
	Version() string

	// Type 返回插件类型
	Type() string

	// Init 初始化插件
	Init(config map[string]interface{}) error

	// Shutdown 关闭插件
	Shutdown() error

	// HealthCheck 健康检查
	HealthCheck(ctx context.Context) error
}

// PluginInfo 插件信息
type PluginInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Version     string `json:"version"`
	Author      string `json:"author"`
	License     string `json:"license"`
}
