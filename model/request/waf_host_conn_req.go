package request

// WafHostConnSearchReq 远程连接看板查询
type WafHostConnSearchReq struct {
	LocalPort int    `json:"local_port" form:"local_port"` // 按本机监听端口筛选，0=不限
	State     string `json:"state" form:"state"`           // ESTABLISHED / LISTEN / ...，留空=不限
	RemoteIP  string `json:"remote_ip" form:"remote_ip"`   // 源IP模糊匹配
	OnlyGuard int    `json:"only_guard" form:"only_guard"` // 1=只看 SSH/RDP 端口
	PageIndex int    `json:"pageIndex" form:"pageIndex"`
	PageSize  int    `json:"pageSize" form:"pageSize"`
}
