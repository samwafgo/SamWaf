package response

// CCEmergencyStatus 紧急模式在某个站点上的状态。
//
// Enable 是库里存的开关，Active 是当前是否真的生效（已开启且未到自动关闭时间）。
// 两个都给：界面要能表达「开着但已过期」这种状态，只给一个的话用户看到的是
// 一个和实际行为对不上的开关。
type CCEmergencyStatus struct {
	HostCode    string `json:"host_code"`
	HostName    string `json:"host_name"`
	GlobalHost  int    `json:"global_host"`
	Enable      int    `json:"enable"`
	Until       int64  `json:"until"`
	Active      bool   `json:"active"`
	GuardStatus int    `json:"guard_status"`
}
