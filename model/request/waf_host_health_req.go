package request

// WafHostHealthTestReq 当前编辑配置的单次健康检测。
type WafHostHealthTestReq struct {
	Code                string `json:"code"`
	Host                string `json:"host"`
	RemoteHost          string `json:"remote_host"`
	RemoteIP            string `json:"remote_ip"`
	RemotePort          int    `json:"remote_port"`
	IsEnableLoadBalance int    `json:"is_enable_load_balance"`
	IsTransBackDomain   int    `json:"is_trans_back_domain"`
	HealthyJSON         string `json:"healthy_json"`
	Offset              int    `json:"offset"`
	Limit               int    `json:"limit"`
}
