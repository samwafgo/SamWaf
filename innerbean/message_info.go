package innerbean

import (
	"SamWaf/wechat"
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
