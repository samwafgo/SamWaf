package wafenginmodel

import "time"

type HostHealthy struct {
	IsHealthy       bool      // 是否健康
	LastCheckTime   time.Time // 最后一次检查时间
	FailCount       int       // 连续失败次数
	SuccessCount    int       // 连续成功次数
	LastErrorReason string    // 最后一次错误原因
	BackIP          string    // 后端IP
	BackPort        int       // 后端端口
}
