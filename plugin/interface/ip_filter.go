package plugininterface

import (
	"context"
)

// IPFilterRequest IP过滤请求
type IPFilterRequest struct {
	IP          string                 `json:"ip"`           // IP地址
	RequestPath string                 `json:"request_path"` // 请求路径
	UserAgent   string                 `json:"user_agent"`   // 用户代理
	Extra       map[string]interface{} `json:"extra"`        // 额外信息
}

// IPFilterResponse IP过滤响应
type IPFilterResponse struct {
	Allowed   bool   `json:"allowed"`    // 是否允许
	Reason    string `json:"reason"`     // 原因
	RiskLevel int    `json:"risk_level"` // 风险等级（0-10）
}

// IPFilterPlugin IP过滤插件接口
type IPFilterPlugin interface {
	Plugin

	// Filter 执行IP过滤
	Filter(ctx context.Context, req *IPFilterRequest) (*IPFilterResponse, error)
}
