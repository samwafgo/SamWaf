package plugininterface

import (
	"context"
)

// WafCheckRequest WAF检查请求
type WafCheckRequest struct {
	RequestID   string                 `json:"request_id"`   // 请求ID
	IP          string                 `json:"ip"`           // 客户端IP
	Method      string                 `json:"method"`       // 请求方法
	URL         string                 `json:"url"`          // 请求URL
	Headers     map[string]string      `json:"headers"`      // 请求头
	Body        string                 `json:"body"`         // 请求体
	QueryParams map[string]string      `json:"query_params"` // 查询参数
	Extra       map[string]interface{} `json:"extra"`        // 额外信息
}

// WafCheckResponse WAF检查响应
type WafCheckResponse struct {
	Allowed   bool                   `json:"allowed"`    // 是否允许通过
	Reason    string                 `json:"reason"`     // 拒绝原因
	RiskLevel int                    `json:"risk_level"` // 风险等级（0-10）
	Action    string                 `json:"action"`     // 建议动作（allow/block/captcha）
	Extra     map[string]interface{} `json:"extra"`      // 额外信息
}

// WafCheckPlugin WAF检查插件接口
type WafCheckPlugin interface {
	Plugin

	// Check 执行WAF检查
	Check(ctx context.Context, req *WafCheckRequest) (*WafCheckResponse, error)
}
