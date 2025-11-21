package response

// IPFailureConfigResp IP失败封禁配置响应
type IPFailureConfigResp struct {
	Enabled     int64  `json:"enabled"`      // 是否启用IP失败封禁 1启用 0禁用
	StatusCodes string `json:"status_codes"` // 失败状态码配置
	LockTime    int64  `json:"lock_time"`    // 封禁锁定时间（分钟）
}

// IPFailureIpResp IP失败封禁IP响应
type IPFailureIpResp struct {
	IP             string `json:"ip"`              // IP地址
	FailCount      int64  `json:"fail_count"`      // 失败次数
	FirstTime      string `json:"first_time"`      // 首次失败时间
	LastTime       string `json:"last_time"`       // 最后失败时间
	RemainTime     string `json:"remain_time"`     // 剩余封禁时间
	Region         string `json:"region"`          // IP归属地
	TriggerMinutes int64  `json:"trigger_minutes"` // 触发封禁的时间窗口（分钟）
	TriggerCount   int64  `json:"trigger_count"`   // 触发封禁的失败次数阈值
}
