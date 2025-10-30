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
	Timestamp       int64   `json:"timestamp"`         // 时间戳
	QPS             uint64  `json:"qps"`               // 当前QPS
	LogQPS          uint64  `json:"log_qps"`           // 日志处理QPS
	MainQueue       int     `json:"main_queue"`        // 主数据队列数量
	LogQueue        int     `json:"log_queue"`         // 日志队列数量
	StatsQueue      int     `json:"stats_queue"`       // 统计队列数量
	MessageQueue    int     `json:"message_queue"`     // 消息队列数量
	CPUPercent      float64 `json:"cpu_percent"`       // CPU使用率
	MemoryPercent   float64 `json:"memory_percent"`    // 内存使用率
	NetworkRecv     uint64  `json:"network_recv"`      // 网络接收字节数(累计)
	NetworkSent     uint64  `json:"network_sent"`      // 网络发送字节数(累计)
	NetworkRecvRate uint64  `json:"network_recv_rate"` // 网络接收速率(字节/秒)
	NetworkSentRate uint64  `json:"network_sent_rate"` // 网络发送速率(字节/秒)
}
