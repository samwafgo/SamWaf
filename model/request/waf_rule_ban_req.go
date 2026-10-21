package request

// WafRuleBanConfigReq 获取规则封禁配置请求
type WafRuleBanConfigReq struct {
}

// WafRuleBanSetConfigReq 设置规则封禁配置请求
type WafRuleBanSetConfigReq struct {
	Mode int64 `json:"mode" form:"mode"` // 封禁执行动作 0返回拦截页 1直接断开
}

// WafRuleBanRemoveBanIpReq 移除规则封禁IP请求
type WafRuleBanRemoveBanIpReq struct {
	HostCode string `json:"host_code" form:"host_code"` // 站点编码
	Ip       string `json:"ip" form:"ip"`               // 移除封禁IP
}
