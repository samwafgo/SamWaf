package plugin

import (
	"SamWaf/common/zlog"
	"SamWaf/globalobj"
	pluginconfig "SamWaf/plugin/config"
	"SamWaf/plugin/manager"
	"SamWaf/utils"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// InitPluginSystem 初始化插件系统
// 从 plugins.yml 配置文件加载插件配置（不使用数据库）
func InitPluginSystem() error {
	zlog.Info("开始初始化插件系统...")

	// 1. 读取插件配置文件
	configPath := filepath.Join(utils.GetCurrentDir(), "conf", "plugins.yml")
	systemConfig, err := loadPluginConfigFromFile(configPath)
	if err != nil {
		zlog.Error("加载插件配置文件失败", "path", configPath, "error", err)
		// 配置文件加载失败不应该阻止系统启动，使用默认配置
		zlog.Info("使用默认插件配置")
		systemConfig = pluginconfig.DefaultPluginSystemConfig()
		systemConfig.Enabled = false // 默认禁用
	}

	// 2. 创建插件管理器
	pluginManager := manager.NewPluginManager(systemConfig)
	globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER = pluginManager

	// 3. 如果插件系统未启用，直接返回
	if !systemConfig.Enabled {
		zlog.Info("插件系统未启用，跳过插件加载")
		return nil
	}

	// 4. 加载每个启用的插件
	loadedCount := 0
	for _, pluginConfig := range systemConfig.List {
		if !pluginConfig.Enabled {
			zlog.Debug("插件未启用，跳过加载", "plugin_id", pluginConfig.ID, "plugin_name", pluginConfig.Name)
			continue
		}

		zlog.Info("加载插件", "plugin_id", pluginConfig.ID, "plugin_name", pluginConfig.Name)
		if err := pluginManager.LoadPlugin(&pluginConfig); err != nil {
			zlog.Error("加载插件失败", "plugin_id", pluginConfig.ID, "error", err)
			continue
		}

		loadedCount++
		zlog.Info("插件加载成功", "plugin_id", pluginConfig.ID, "plugin_name", pluginConfig.Name)
	}

	zlog.Info("插件系统初始化完成", "总插件数", len(systemConfig.List), "已加载", loadedCount)
	return nil
}

// loadPluginConfigFromFile 从 YAML 配置文件加载插件配置
func loadPluginConfigFromFile(configPath string) (*pluginconfig.PluginSystemConfig, error) {
	// 检查文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("配置文件不存在: %s", configPath)
	}

	// 读取文件内容
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 定义配置文件结构
	type ConfigFile struct {
		Plugins pluginconfig.PluginSystemConfig `yaml:"plugins"`
	}

	var configFile ConfigFile
	if err := yaml.Unmarshal(data, &configFile); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	zlog.Info("成功加载插件配置文件",
		"enabled", configFile.Plugins.Enabled,
		"plugin_count", len(configFile.Plugins.List))

	return &configFile.Plugins, nil
}

// SavePluginConfigToFile 保存插件配置到文件
// 供 API 使用，用于在线修改配置
func SavePluginConfigToFile(systemConfig *pluginconfig.PluginSystemConfig) error {
	configPath := filepath.Join(utils.GetCurrentDir(), "conf", "plugins.yml")

	// 构造配置文件结构
	type ConfigFile struct {
		Plugins pluginconfig.PluginSystemConfig `yaml:"plugins"`
	}

	configFile := ConfigFile{
		Plugins: *systemConfig,
	}

	// 序列化为 YAML
	data, err := yaml.Marshal(&configFile)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	// 备份原配置文件
	backupPath := configPath + ".backup"
	if _, err := os.Stat(configPath); err == nil {
		os.Rename(configPath, backupPath)
	}

	// 写入文件
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		// 如果写入失败，恢复备份
		if _, err := os.Stat(backupPath); err == nil {
			os.Rename(backupPath, configPath)
		}
		return fmt.Errorf("写入配置文件失败: %w", err)
	}

	zlog.Info("插件配置已保存", "path", configPath)
	return nil
}

// ShutdownPluginSystem 关闭插件系统
func ShutdownPluginSystem() error {
	if globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER == nil {
		return nil
	}

	zlog.Info("关闭插件系统...")
	return globalobj.GWAF_RUNTIME_OBJ_PLUGIN_MANAGER.Shutdown()
}
