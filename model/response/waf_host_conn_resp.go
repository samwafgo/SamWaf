package response

// HostConnItem 一条远程连接
type HostConnItem struct {
	RemoteIP   string `json:"remote_ip"`   // 对端IP
	RemotePort int    `json:"remote_port"` // 对端端口
	LocalIP    string `json:"local_ip"`    // 本机IP
	LocalPort  int    `json:"local_port"`  // 本机端口
	State      string `json:"state"`       // ESTABLISHED / LISTEN / TIME_WAIT ...
	Pid        int32  `json:"pid"`         //
	ProcName   string `json:"proc_name"`   // 进程名，取不到为空
	Location   string `json:"location"`    // 归属地
	IsGuard    bool   `json:"is_guard"`    // 是否命中 SSH/RDP 端口(前端高亮用)
	Banned     bool   `json:"banned"`      // 该IP当前是否已被主机防爆破封禁
}

// HostConnPortStat 按本机端口聚合
type HostConnPortStat struct {
	Port    int    `json:"port"`
	Count   int    `json:"count"`
	IsGuard bool   `json:"is_guard"`
	Label   string `json:"label"` // SSH / RDP / 其他
}

// HostConnIPStat 按对端IP聚合
type HostConnIPStat struct {
	RemoteIP string `json:"remote_ip"`
	Count    int    `json:"count"`
	Location string `json:"location"`
}

// HostConnSummary 连接看板汇总
type HostConnSummary struct {
	Total       int                `json:"total"`       // 连接总数
	Established int                `json:"established"` // 已建立连接数
	Listen      int                `json:"listen"`      // 监听端口数
	GuardConns  int                `json:"guard_conns"` // 落在 SSH/RDP 端口上的连接数
	SSHPorts    []int              `json:"ssh_ports"`   // 探测到的 SSH 端口
	RDPPorts    []int              `json:"rdp_ports"`   // 探测到的 RDP 端口
	TopPorts    []HostConnPortStat `json:"top_ports"`   //
	TopIPs      []HostConnIPStat   `json:"top_ips"`     //
	CollectMs   int64              `json:"collect_ms"`  // 本次采集耗时(毫秒)
	FromCache   bool               `json:"from_cache"`  // 是否命中快照缓存
	Unavailable string             `json:"unavailable"` // 非空表示采集不可用的中文原因
}
