package config

// PluginSystemConfig 插件系统配置
type PluginSystemConfig struct {
	Enabled             bool           `yaml:"enabled" json:"enabled"`                             // 插件系统是否启用
	BinaryDir           string         `yaml:"binary_dir" json:"binary_dir"`                       // 插件二进制文件目录
	LogDir              string         `yaml:"log_dir" json:"log_dir"`                             // 插件日志目录
	ConfigDir           string         `yaml:"config_dir" json:"config_dir"`                       // 插件配置目录
	Timeout             int            `yaml:"timeout" json:"timeout"`                             // 插件通信超时时间（秒）
	LogLevel            string         `yaml:"log_level" json:"log_level"`                         // go-plugin 框架日志级别 (off/error/warn/info/debug/trace)
	AutoRestart         bool           `yaml:"auto_restart" json:"auto_restart"`                   // 是否启用自动重启
	RestartInterval     int            `yaml:"restart_interval" json:"restart_interval"`           // 重启间隔（秒）
	MaxRestartCount     int            `yaml:"max_restart_count" json:"max_restart_count"`         // 最大重启次数（-1 表示无限制）
	HealthCheckInterval int            `yaml:"health_check_interval" json:"health_check_interval"` // 健康检查间隔（秒）
	List                []PluginConfig `yaml:"list" json:"list"`                                   // 插件列表
}

// PluginConfig 单个插件配置
type PluginConfig struct {
	ID           string                 `yaml:"id" json:"id"`                       // 插件唯一ID
	Name         string                 `yaml:"name" json:"name"`                   // 插件名称
	Description  string                 `yaml:"description" json:"description"`     // 插件描述
	Type         string                 `yaml:"type" json:"type"`                   // 插件类型
	Version      string                 `yaml:"version" json:"version"`             // 插件版本
	Enabled      bool                   `yaml:"enabled" json:"enabled"`             // 是否启用
	BinaryPath   string                 `yaml:"binary_path" json:"binary_path"`     // 插件二进制路径
	Priority     int                    `yaml:"priority" json:"priority"`           // 优先级（数字越大优先级越高）
	Groups       []string               `yaml:"groups" json:"groups"`               // 插件分组
	Params       map[string]interface{} `yaml:"params" json:"params"`               // 插件参数
	InputSchema  []FieldSchema          `yaml:"input_schema" json:"input_schema"`   // 输入参数定义
	OutputSchema []FieldSchema          `yaml:"output_schema" json:"output_schema"` // 输出参数定义
}

// FieldSchema 字段定义
type FieldSchema struct {
	Name        string `yaml:"name" json:"name"`               // 字段名称
	Type        string `yaml:"type" json:"type"`               // 字段类型
	Required    bool   `yaml:"required" json:"required"`       // 是否必填
	Description string `yaml:"description" json:"description"` // 字段描述
}

// DefaultPluginSystemConfig 默认插件系统配置
func DefaultPluginSystemConfig() *PluginSystemConfig {
	return &PluginSystemConfig{
		Enabled:             true,
		BinaryDir:           "./data/plugins/binaries",
		LogDir:              "./data/plugins/logs",
		ConfigDir:           "./data/plugins/configs",
		Timeout:             30,
		LogLevel:            "warn", // 默认只显示警告和错误
		AutoRestart:         true,   // 默认启用自动重启
		RestartInterval:     3,      // 3 秒重启间隔
		MaxRestartCount:     5,      // 最多重启 5 次
		HealthCheckInterval: 10,     // 10 秒健康检查间隔
		List:                []PluginConfig{},
	}
}
