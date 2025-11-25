package innerbean

import (
	"SamWaf/utils/wechat"
)

type BaseInfo interface {
	ToFormat() string
}

/***

信息类型:
服务器:
IP地址:

*/

type BaseMessageInfo struct {
	OperaType string `json:"operatype"`
	Server    string `json:"server"`
}

/*
**
域名信息:
触发规则:
*/
type RuleMessageInfo struct {
	BaseMessageInfo
	Domain   string `json:"domain"`
	RuleInfo string `json:"ruleinfo"`
	Ip       string `json:"ip"`
}

/*
*
升级结果
*/
type UpdateResultMessageInfo struct {
	BaseMessageInfo
	Msg     string `json:"msg"`
	Success string `json:"success"`
}

/*
*
导出日志结果
*/
type ExportResultMessageInfo struct {
	BaseMessageInfo
	Msg     string `json:"msg"`
	Success string `json:"success"`
}

/*
*
实时操作反馈
*/
type OpResultMessageInfo struct {
	BaseMessageInfo
	Msg     string `json:"msg"`
	Success string `json:"success"`
}

/*
*
用户登录信息
*/
type UserLoginMessageInfo struct {
	BaseMessageInfo
	Username string `json:"username"` // 用户名
	Ip       string `json:"ip"`       // 登录IP
	Time     string `json:"time"`     // 登录时间
}

/*
*
攻击信息
*/
type AttackInfoMessageInfo struct {
	BaseMessageInfo
	AttackType string `json:"attack_type"` // 攻击类型
	Url        string `json:"url"`         // 攻击URL
	Ip         string `json:"ip"`          // 攻击IP
	Time       string `json:"time"`        // 攻击时间
}

/*
*
周报信息
*/
type WeeklyReportMessageInfo struct {
	BaseMessageInfo
	TotalRequests   int64  `json:"total_requests"`   // 总请求数
	BlockedRequests int64  `json:"blocked_requests"` // 拦截请求数
	WeekRange       string `json:"week_range"`       // 周期范围
}

/*
*
SSL证书过期信息
*/
type SSLExpireMessageInfo struct {
	BaseMessageInfo
	Domain     string `json:"domain"`      // 域名
	ExpireTime string `json:"expire_time"` // 过期时间
	DaysLeft   int    `json:"days_left"`   // 剩余天数
}

/*
*
系统错误信息
*/
type SystemErrorMessageInfo struct {
	BaseMessageInfo
	ErrorType string `json:"error_type"` // 错误类型
	ErrorMsg  string `json:"error_msg"`  // 错误信息
	Time      string `json:"time"`       // 发生时间
}

/*
*
IP封禁信息
*/
type IPBanMessageInfo struct {
	BaseMessageInfo
	Ip       string `json:"ip"`       // IP地址
	Reason   string `json:"reason"`   // 封禁原因
	Duration int    `json:"duration"` // 封禁时长（分钟）
	Time     string `json:"time"`     // 封禁时间
}

func (r RuleMessageInfo) ToFormat() map[string]*wechat.DataItem {
	Data := map[string]*wechat.DataItem{}
	Data["domain"] = &wechat.DataItem{
		Value: r.Domain,
		Color: "#808080",
	}
	Data["ruleinfo"] = &wechat.DataItem{
		Value: r.RuleInfo,
		Color: "#808080",
	}
	Data["ip"] = &wechat.DataItem{
		Value: r.Ip,
		Color: "#808080",
	}
	Data["server"] = &wechat.DataItem{
		Value: r.Server,
		Color: "#808080",
	}
	Data["operatype"] = &wechat.DataItem{
		Value: r.OperaType,
		Color: "#808080",
	}
	return Data
}

func (r OperatorMessageInfo) ToFormat() map[string]*wechat.DataItem {
	Data := map[string]*wechat.DataItem{}
	Data["operacnt"] = &wechat.DataItem{
		Value: r.OperaCnt,
		Color: "#808080",
	}
	Data["server"] = &wechat.DataItem{
		Value: r.Server,
		Color: "#808080",
	}
	Data["operatype"] = &wechat.DataItem{
		Value: r.OperaType,
		Color: "#808080",
	}
	return Data
}

/*
**
信息内容:
*/
type OperatorMessageInfo struct {
	BaseMessageInfo
	OperaCnt string `json:"operacnt"`
}

// SystemStatsData 系统统计数据结构，用于ECharts展示
type SystemStatsData struct {
	BaseMessageInfo
	Timestamp       int64       `json:"timestamp"`         // 时间戳
	QPS             uint64      `json:"qps"`               // 当前QPS
	LogQPS          uint64      `json:"log_qps"`           // 日志处理QPS
	MainQueue       int         `json:"main_queue"`        // 主数据队列数量
	LogQueue        int         `json:"log_queue"`         // 日志队列数量
	StatsQueue      int         `json:"stats_queue"`       // 统计队列数量
	MessageQueue    int         `json:"message_queue"`     // 消息队列数量
	CPUPercent      float64     `json:"cpu_percent"`       // CPU使用率
	MemoryPercent   float64     `json:"memory_percent"`    // 内存使用率
	NetworkRecv     uint64      `json:"network_recv"`      // 网络接收字节数(累计)
	NetworkSent     uint64      `json:"network_sent"`      // 网络发送字节数(累计)
	NetworkRecvRate uint64      `json:"network_recv_rate"` // 网络接收速率(字节/秒)
	NetworkSentRate uint64      `json:"network_sent_rate"` // 网络发送速率(字节/秒)
	SystemMonitor   interface{} `json:"system_monitor"`    // 完整的系统监控信息
}
