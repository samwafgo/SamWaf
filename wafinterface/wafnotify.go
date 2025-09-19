package wafinterface

import "SamWaf/innerbean"

type WafNotify interface {
	NotifyBatch(logs []*innerbean.WebLog) error // 处理多个日志
	NotifySingle(log *innerbean.WebLog) error   // 处理单个日志
}
