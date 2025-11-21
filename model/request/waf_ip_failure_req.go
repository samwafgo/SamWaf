package request

// WafIPFailureConfigReq 获取IP失败封禁配置请求
type WafIPFailureConfigReq struct {
}

// WafIPFailureSetConfigReq 设置IP失败封禁配置请求
type WafIPFailureSetConfigReq struct {
	Enabled     int64  `json:"enabled" form:"enabled"`           // 是否启用IP失败封禁 1启用 0禁用
	StatusCodes string `json:"status_codes" form:"status_codes"` // 失败状态码配置
	LockTime    int64  `json:"lock_time" form:"lock_time"`       // 封禁锁定时间（分钟）
}

// WafIPFailureRemoveBanIpReq 移除封禁IP请求
type WafIPFailureRemoveBanIpReq struct {
	Ip string `json:"ip" form:"ip"` //移除封禁IP
}
