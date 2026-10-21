package response

// RuleBanConfigResp 规则封禁配置响应
type RuleBanConfigResp struct {
	Mode int64 `json:"mode"` // 封禁执行动作 0返回拦截页 1直接断开
}

// RuleBanIpResp 规则封禁IP响应
type RuleBanIpResp struct {
	IP         string `json:"ip"`          // IP地址
	HostCode   string `json:"host_code"`   // 站点编码
	HostName   string `json:"host_name"`   // 站点名称（解析失败时为空）
	BanMinutes int64  `json:"ban_minutes"` // 封禁时长（分钟）
	RemainTime string `json:"remain_time"` // 剩余封禁时间
	Region     string `json:"region"`      // IP归属地
}
