package model

import (
	"SamWaf/model/baseorm"
)

// WafPluginConfig 插件配置表
type WafPluginConfig struct {
	baseorm.BaseOrm
	PluginID     string `json:"plugin_id" gorm:"uniqueIndex;type:varchar(100);not null;comment:插件唯一ID"` // 插件唯一ID
	Name         string `json:"name" gorm:"type:varchar(100);not null;comment:插件名称"`                    // 插件名称
	Description  string `json:"description" gorm:"type:text;comment:插件描述"`                              // 插件描述
	Type         string `json:"type" gorm:"type:varchar(50);not null;comment:插件类型"`                     // 插件类型
	Version      string `json:"version" gorm:"type:varchar(20);not null;comment:插件版本"`                  // 插件版本
	Enabled      int    `json:"enabled" gorm:"default:1;comment:是否启用 1启用 0禁用"`                          // 是否启用（1启用，0禁用）
	BinaryPath   string `json:"binary_path" gorm:"type:varchar(500);not null;comment:插件二进制路径"`          // 插件二进制路径
	Priority     int    `json:"priority" gorm:"default:50;comment:优先级 数字越大优先级越高"`                       // 优先级
	Groups       string `json:"groups" gorm:"type:text;comment:插件分组 JSON数组"`                            // 插件分组（JSON数组）
	Params       string `json:"params" gorm:"type:text;comment:插件参数 JSON对象"`                            // 插件参数（JSON对象）
	InputSchema  string `json:"input_schema" gorm:"type:text;comment:输入参数定义 JSON"`                      // 输入参数定义（JSON）
	OutputSchema string `json:"output_schema" gorm:"type:text;comment:输出参数定义 JSON"`                     // 输出参数定义（JSON）
}

// WafPluginLog 插件执行日志表
type WafPluginLog struct {
	baseorm.BaseOrm
	PluginID      string `json:"plugin_id" gorm:"type:varchar(100);not null;index;comment:插件ID"` // 插件ID
	RequestID     string `json:"request_id" gorm:"type:varchar(100);index;comment:请求ID"`         // 请求ID
	InputData     string `json:"input_data" gorm:"type:text;comment:输入数据 JSON"`                  // 输入数据（JSON）
	OutputData    string `json:"output_data" gorm:"type:text;comment:输出数据 JSON"`                 // 输出数据（JSON）
	ExecutionTime int64  `json:"execution_time" gorm:"comment:执行时间 毫秒"`                          // 执行时间（毫秒）
	Status        string `json:"status" gorm:"type:varchar(20);comment:执行状态 success/error"`      // 执行状态（success/error）
	ErrorMsg      string `json:"error_msg" gorm:"type:text;comment:错误信息"`                        // 错误信息
}

// WafPluginSystemConfig 插件系统配置表
type WafPluginSystemConfig struct {
	baseorm.BaseOrm
	Key         string `json:"key" gorm:"uniqueIndex;type:varchar(100);not null;comment:配置键"` // 配置键
	Value       string `json:"value" gorm:"type:text;comment:配置值"`                            // 配置值
	Description string `json:"description" gorm:"type:text;comment:配置描述"`                     // 配置描述
}
